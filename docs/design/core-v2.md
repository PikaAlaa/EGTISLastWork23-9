# ETIS core v2 — STIX export, recommended actions, device risk and de-fanged display

Status: **design only** (26 November 2026), with the owner's review answers of
27 November 2026 (§7.1). Branch `feat/core-v2-design`, rebased onto `origin/main` at
`bf67aae`. That commit includes the `network.windows` engine (PR #29, `062be8f`) and the
[Windows agent and LAN server design](windows-agent-lan-v1.md) (PR #32). No code, schema,
migration, download or behaviour change accompanies this document. A fact about an external
standard or licence is marked **verified** only when it was read on the cited page, and a
fact about this repository only when it was read in its code. Every other fact is marked
**to verify** and listed again in §8. No number in this document comes from a measurement.

Core v2 adds four platform features on top of [core v1](core-v1.md) (Findings, indicator
store, incidents, ATT&CK) and the engines built since:

| # | Feature | Requirement |
| --- | --- | --- |
| 1 | Offline STIX 2.1 export of indicators and incidents to a local file | FR-12 |
| 2 | A fixed, reviewed recommended action attached to every Finding, in Arabic and English | FR-14 |
| 3 | A cross-engine, rule-based risk score per device, with its explanation | — (serves the FR-11 per-device view) |
| 4 | De-fanged indicators (`hxxps://evil[.]com`) everywhere in the console | — |

Requirement wording (team requirements list, given by the owner on 27 November 2026):

| Id | Requirement | Relation to core v2 |
| --- | --- | --- |
| FR-11 | Windows agent on each PC sending Findings to a company LAN server. | Designed in [windows-agent-lan-v1](windows-agent-lan-v1.md). Core v2's device attribution and score must fit the agent's `device_ref` (§3.6). |
| FR-12 | Export incidents and indicators as STIX 2.1. | §1. |
| FR-13 | Browser extension that checks links before they open. | Designed in [browser-extension-v1](browser-extension-v1.md). Not changed here. The extension can reuse `defang-v1` (§4.2) wherever it shows a value. |
| FR-14 | Recommended action attached to every Finding. | §2. "Every" is met by the kind default and the fallback (§2.3), so no Finding is left without an action. |

## 0. Constraints this design must keep

| Constraint | How core v2 keeps it |
| --- | --- |
| Free and local only | Python standard library and existing dependencies only. The export is a CLI that writes a file on the owner's disk. Nothing is uploaded, posted, shared through TAXII or sent by e-mail. |
| URLs are inert strings | No feature resolves, fetches or opens an indicator. The export never contacts a STIX/TAXII server or a validator service. De-fanging (§4) adds a second, display-level guard on top of the existing non-clickable `InertValue`. |
| Verdicts, thresholds, frozen models, v4 rule and selection unchanged | All four features read stored Findings after they are recorded. None of them is read by `calculate_final_risk_score`, by an engine or by correlation. `AnalyzeResponse` gets no new field, so the `/analyze` parity gate (`backend/tests/test_findings_parity.py`) stays as it is. |
| Frozen engines unchanged | The malware v1 rule (frozen in #31), the host and network-windows rule lists, and the phishing mapping are not edited. Device attribution (§3.2) is added by `record_findings` and the import commands, not inside engine logic. |
| Privacy minimization | Scan-derived indicators remain hash-only and are **never exported** (§1.4). Pseudonyms (`host_ref`, `device_ref`, `account_ref`, `path_ref`), analyst notes and `evidence.details` are never exported. The device score is computed when it is read and never stored. |
| Data licences (`docs/data-licences.md`) | The export writes only values from redistributable sources: analyst, community, and the CC0 abuse.ch lists. OpenPhish and PhishTank values are never exported, only counted (§1.4). |
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
                                   [--include-resolved-benign] [--tlp amber|green|white]
                                   [--out PATH]
```

- **Scope.** By default the export holds open and investigating incidents. With `--incident`
  it holds the named incidents; with `--since` it holds incidents with activity on or after
  that date. Incidents resolved `false_positive` or `benign` are left out unless
  `--include-resolved-benign` is given, because they would distribute wrong indicators.
- **Output.** The default is `var/exports/etis-stix-<UTC yyyymmddThhmmssZ>.json` (`var/` is
  already ignored by Git). The command refuses to overwrite an existing file, writes to a
  temporary name and then renames, and prints only the path, object counts and the number
  of indicators counted but not exported (§1.4). It never prints indicator values.
- **No network.** The script imports no HTTP library and opens no socket. A test runs it with
  `socket.socket` patched to raise (§6, step 4).
- **Deterministic.** The same database state and arguments give the same bytes, apart from
  the bundle id and the export timestamp. Objects are sorted by type and then by id.

### 1.2 Object mapping

STIX object types and properties named here follow the STIX 2.1 specification (**to verify**
against the OASIS 2.1 specification text, §8 V1–V6, before step 3). Checked on 27 November
2026 (§8) against the specification text up to §4.16, the OASIS `cti-stix2-json-schemas` and
the OASIS `cti-python-stix2` library. The rules the exporter relies on, with these sources,
are committed as `backend/app/resources/stix21-subset-v1.json`.

| ETIS source | STIX 2.1 object | Mapping |
| --- | --- | --- |
| The ETIS installation | `identity` | `name: "ETIS local instance"`, `identity_class: "system"`. Every other object has `created_by_ref` pointing to it. It never names the owner, the team or an organisation. |
| `incidents` row | `incident` | `name` = `title`; `description` = fixed text "Exported from ETIS. Status and severity are ETIS categories."; `created` = `opened_at`; `modified` = `last_activity_at`; custom `x_etis_status`, `x_etis_severity`, `x_etis_resolution`, `x_etis_domain`, `x_etis_finding_counts` (counts by kind, engine and severity, including findings whose indicators were counted but not exported). Analyst notes (`incident_events.note`) are **not** exported. |
| `indicators` row linked to an exported incident that passes the licence filter (§1.4) | `indicator` | `pattern` per §1.3, with the **real** value; `pattern_type: "stix"`; `valid_from` = `first_seen`; `indicator_types: ["malicious-activity"]`; custom `x_etis_type` and `x_etis_sources`. `x_etis_sources` lists only the redistributable sources the value was taken from (e.g. `analyst:manual`, `community:community_reports`, `list:feodo_tracker`), never a restricted feed. |
| `findings` row ↔ exported indicator (`finding_indicators`) | `sighting` | `sighting_of_ref` = the indicator; `first_seen` = `last_seen` = `observed_at`; `count: 1`; `where_sighted_refs` = ETIS identity; custom `x_etis_finding_id`, `x_etis_engine` (name and version), `x_etis_kind`, `x_etis_severity`, `x_etis_confidence`, `x_etis_reasons` (reason codes only). `evidence.details` is not exported. |
| `finding_attack` technique used by an exported finding | `attack-pattern` | `id` = an ETIS-namespace UUIDv5 over matrix, ATT&CK version and technique id (owner decision, 28 November 2026, §7.1.1 D1). MITRE's `stix_id` is **not** reused: ETIS does not store MITRE's `created`/`modified`, and re-publishing MITRE's id with ETIS timestamps and markings would be a conflicting version of MITRE's object. Consumers match the technique by `external_references: [{source_name: "mitre-attack", external_id, url}]`; MITRE's id is kept in `x_etis_mitre_stix_id`. `name` from the local v20.0 catalogue. A technique that is not in the catalogue is exported as an `x_etis_attack_ids` value on the incident, not as an object. |
| Incident ↔ indicator / attack pattern | `relationship` | `incident related-to indicator`; `incident related-to attack-pattern` (with custom `x_etis_basis`, the mapping basis codes); `indicator indicates attack-pattern` when the indicator's finding carries that technique. |
| Export-wide | `marking-definition` (TLP) | All objects carry `object_marking_refs` to the TLP marking chosen by `--tlp` (default AMBER, open question Q3). STIX 2.1 has only the four built-in TLP 1.0 markings (WHITE, GREEN, AMBER, RED), so the option offers `white`, with the help text "TLP:WHITE (STIX 2.1 built-in TLP 1.0 marking; TLP 2.0 calls it CLEAR)" (owner decision, §7.1.1 D2). |
| Export-wide | `note` | The human-readable summary (§1.5): the required ATT&CK notice ("Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.", `docs/data-licences.md`), the licence of each source used (CC0 for abuse.ch lists), a **de-fanged** list of the exported indicator values, and the counts of values not exported, by reason. `object_refs` is set to the incidents. |

Not exported: campaigns (analyst-created groupings, often still in progress; listed as open
question Q5), `indicator_sightings` rows without a finding (the feed projection), device
pseudonyms, `path_ref`, account pseudonyms, scan requests and results, and the text of
community reports (only a confirmed report's normalized value, as an indicator).

**Numeric confidence.** STIX has an integer `confidence` property (0–100, **to verify**, V4).
ETIS does **not** fill it. ETIS confidence is categorical because its scores are indicator
strengths, not calibrated probabilities (core v1 §1.1). A number would mislead the recipient.
The category is exported as `x_etis_confidence`.

**Incident extension.** The 2.1 `incident` object is minimal. OASIS has published an
incident core extension (**to verify**, V5). v2 uses only `x_etis_*` custom properties,
because they are simple and need no extension definition. Moving to the extension is open
question Q4.

### 1.3 Patterns per indicator type

| ETIS type | Pattern (real values; the examples use reserved documentation names and addresses) |
| --- | --- |
| `url` | `[url:value = 'https://login.evil.example/verify']` |
| `domain` | `[domain-name:value = 'evil.example']` |
| `ip` (v4 / v6) | `[ipv4-addr:value = '203.0.113.7']` / `[ipv6-addr:value = '2001:db8::1']` |
| `email` | `[email-addr:value = 'payroll@evil.example']` |
| `hash` | `[file:hashes.'SHA-256' = '…']` (also `SHA-1`, `MD5` by `hash_algo`) |
| `phone` | **No pattern.** STIX 2.1 has no telephone-number observable (**to verify**, V3). Phone indicators are exported only as a count on the incident. |

Values in a pattern are escaped as STIX string literals (backslash and single quote). The
patterns are built by one pure function, `app/services/stix_export.py::pattern_for(type, value, algo)`.

### 1.4 Licence filter: what is exported, what is only counted

An indicator is exported **only** when its plaintext value comes from a source whose licence
allows redistribution (owner decision, 27 November 2026). Every other indicator linked to
an exported incident is **counted** by type and reason in the `note` and in the command's
output, and its value is never written.

| Source (`indicator_sightings.source_kind:source_name`, or list) | Where the plaintext comes from | Licence status | Export |
| --- | --- | --- | --- |
| Analyst-entered (`feed:manual` blacklist entries; `analyst:*` sightings) | `indicators.value` | ETIS team's own entries. | **Yes, unless restricted-feed check fails** (owner decision Q14, rule below). |
| Community (`community:community_reports`, confirmed only) | `indicators.value` of the confirmed report | Values reported to this ETIS installation and confirmed by an analyst. | **Not yet; counted only** (owner decision Q15). A value becomes exportable only after the submission form states that values are shared under CC0 and the reporter has accepted that. The acceptance is recorded per report (rule below). No submission form exists today (core v1 §2.5). |
| abuse.ch Feodo Tracker IP blocklist (`feodo_tracker`) | Local pinned list file under ignored `data/external/network-blocklists/` (§1.4.1) | **CC0**. abuse.ch terms of use §3.4: "Feodo Tracker, SSL Blacklist, and YARAify are free to use without limitations according to Creative Commons principles (CC0)". Recorded in `docs/data-licences.md` (`abuse_ch_network_blocklists`) as read by the reviewer on 2026-11-25; **not re-read for this document** (**to verify**, V10). | **Yes** |
| OpenPhish (`feed:openphish`) | `blacklist_entries` / `indicators.value` | Proprietary. Recorded in `docs/data-licences.md`: "Except as expressly permitted by OpenPhish in writing"; redistribution "not permitted by current terms without written permission". Not re-read for this document (**to verify**, V11). | **Never**, count only |
| PhishTank (`feed:phishtank`) | as above | Not established. Recorded in `docs/data-licences.md`: the current terms link to a Cisco EULA, and the CC BY-SA 2.5 statement exists only in archived terms. Not re-read for this document (**to verify**, V11). | **Never**, count only |
| Scan-derived (phishing scans, provider checks, e-mail imports, host and network-windows destinations, agent `sensor` findings) | none: hash-only (`value` NULL) | n/a (the user's or employee's own data) | **Never**, count only |
| Malware file hashes | none: stored as SHA-256 of the file's SHA-256 | n/a | **Never**, count only (Q2) |
| Any other or unknown source | — | not recorded | **Never**, count only. A new source becomes exportable only through a `docs/data-licences.md` entry and a change to the allowlist below. |

**Rules.**

- **Allowlist.** The allowlist is a fixed constant, `EXPORTABLE_SOURCES`, in
  `stix_export.py`. Each entry cites its `docs/data-licences.md` entry, and the tests pin
  the list (§6, step 4).
- **Restricted-feed check for analyst values (Q14).** An analyst-entered value is **not
  exported**, and is counted as `restricted_feed_overlap`, when either of these holds:
  1. its **declared source** is OpenPhish or PhishTank. For `analyst:*` sightings the
     declared source is `indicator_sightings.source_name`. The analyst entry form offers a
     fixed list, `own_investigation | openphish | phishtank | other`, so no new column is
     needed. `feed:manual` blacklist entries carry no declared source and are checked by
     rule 2 only.
  2. the value **also appears in any stored OpenPhish or PhishTank record**, active or
     inactive, past or current:
     - `url`: the `url_hash` in `feed_observations` or `blacklist_entries` with source
       `openphish` / `phishtank`, or in an accepted or rejected `feed_snapshots` payload of
       those sources;
     - `domain`: equal to the `domain` of such a `blacklist_entries` row or the host of such
       a snapshot URL;
     - any type: an `indicator_sightings` row `feed:openphish` / `feed:phishtank`.

  The check only reads the feed tables, as the feed path requires (core v1 §2.1). A later
  expiry or rollback of the feed row does not make the value exportable again, because the
  check covers every stored record.
- **Community values (Q15).** Exported only when the report row carries
  `licence_accepted = 'CC0-1.0'` and `licence_notice_version`. Both are recorded when the
  reporter accepts the CC0 statement on the future submission form. Until that form exists,
  every community value is counted as `community_licence_not_accepted`. The two columns
  belong to the migration of the submission feature, not to core v2's `009`. Even with CC0
  accepted, the **same restricted-feed check** as for analyst values applies (owner decision
  Q18). A community value that appears in any stored OpenPhish or PhishTank record is
  counted as `restricted_feed_overlap`, because a reporter could submit a value copied from
  a restricted feed. Community reports have no declared source, so only rule 2 applies.
- **CC0 list values** are exported on the strength of their own licence (§1.4.1).
- **`x_etis_sources`** lists only the allowed sources a value was exported from.
- **Counted values stay out.** A value that is only counted never appears in any form:
  pattern, `note`, object id or hash. ETIS also does not export the unkeyed SHA-256 of a
  scan-derived value: anyone who guesses the value can confirm it (core v1 §2.2), so
  exporting the hash would publish what the user scanned.

#### 1.4.1 Recovering CC0 list values for network.windows matches

`network.windows` N1 Findings carry the remote IP **hash-only** (`value` NULL), even when
the IP came from a public list (**verified** in `backend/app/engines/network_windows/engine.py`,
`indicators()`). The exporter recovers the plaintext without storing it. It reads the
locally pinned Feodo Tracker file, accepting the file only when its
lock-file SHA-256 matches, as `blocklists.py` does. It hashes each listed IP with the core v1
normalization, and it exports an indicator only when its `value_hash` is in that set. Three
consequences follow:

- Only IPs that are **in a CC0 list** are exported. Any other IP seen on the device stays a
  count.
- When the lists are not installed on the machine that runs the export, for example a LAN
  server where the lists were never fetched, these indicators are counted with the reason
  `list_not_installed`. Nothing is fetched.
- The recovered value is used only while the bundle is written. It is not written back to
  `indicators.value`.

### 1.5 Real values in patterns; de-fanging only for people

Owner decision (27 November 2026, was Q1): patterns carry **real, canonical values**, because
the recipient's tools must match them. After the licence filter (§1.4), every exported value
is shareable. De-fanging (§4.2) applies only to what a person reads:

1. the console (§4);
2. the bundle `note`'s human-readable list of exported values, which is de-fanged with
   `defang-v1` and headed "Values below are de-fanged for safe reading; the indicator
   patterns hold the real values";
3. nothing else. Patterns, object ids and `x_etis_*` properties are never de-fanged.
   The SCO `defanged` property is not used, because v2 exports no SCOs.

The command still prints no values to the terminal (§1.1).

### 1.6 Identifiers

- **SDOs and relationships:** UUIDv5 over `"<table>:<row id>[:<related id>]"` in a namespace
  derived from a per-installation `ETIS_STIX_NAMESPACE` UUID, which `scripts/initialize.py`
  generates into ignored `.env` as it does the pseudonym keys. Re-exports keep ids stable,
  and two ETIS installations never collide.
- **Attack patterns:** ETIS-namespace UUIDv5 over `attack:<matrix>:<version>:<technique>`,
  with MITRE's id in `x_etis_mitre_stix_id` (§1.2).
- **Marking definitions:** the fixed TLP 1.0 ids built into STIX 2.1 (**verified**, V6), for
  example TLP:AMBER `marking-definition--f88d31f6-486f-44da-b317-01333bde0b82`, all with
  `created` `2017-01-20T00:00:00.000Z`.
- **UUID version:** the specification says SDOs and SROs SHOULD use UUIDv4. Producers using
  another version must avoid collisions and must not use the SCO UUIDv5 namespace (§2.9,
  **verified**). The per-installation namespace does that, and the SCO namespace is refused.
  The schema's id pattern accepts UUID versions 1–5 (**verified**). Bundle ids are UUIDv4.
- **Timestamps:** RFC 3339 UTC with a `Z` suffix and millisecond precision; `spec_version:
  "2.1"` on every object.

### 1.7 Validation without network

Unit tests check the output against a small **committed rules subset**,
`backend/app/resources/stix21-subset-v1.json`, written by the team from the sources in §8.
It covers the required properties of the eight object types used, the id format, the
timestamp format, the vocabularies used, the reserved property names and the TLP 1.0
markings. `app.services.stix_export.validate_object` and `validate_bundle` check it. No
JSON Schema library is installed, and none is added. The OASIS `stix2-validator` could be
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
- **Review.** Each entry starts as `draft`. It becomes `reviewed` only when the reviewer
  checks the English and the Arabic text. The reviewer is **a team member named by the owner
  before release** (owner decision, 27 November 2026, was Q12). `reviewed_by` records the
  reviewer's role, not their name, together with a date. Until then every entry stays
  `draft` and is hidden (§2.3). A change to a reviewed text resets its status to `draft`
  and bumps the catalogue `version`. The catalogue goes through code review like any rule
  table.

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
| `network.windows` | `detections.REASONS` (**verified** in `backend/app/engines/network_windows/detections.py`), the 15 codes of N1–N9 below. The module already has the declaration, so no `REASON_CODES` constant is added. |
| `host.windows` | Its rule codes (H1–H13 and the Sigma harness) once the engine emits Findings. Its entries are written in the step that registers it. |

`network.windows` codes and their kinds (`engine.py` `KINDS`, **verified**). The action
entries are written in step 5. The direction column is guidance for the reviewer, not final
text:

| Rule | Kind | Reason codes | Action direction (`user` unless noted) |
| --- | --- | --- | --- |
| N1 | `known_bad_destination` | `blocklist_ip_connection`, `blocklist_ip_dropped`, `blocklist_ip_dns_answer` | Connection made: the PC contacted an address on a public malware-infrastructure list; disconnect it from the network and ask IT support to check it. Dropped: the firewall blocked it; still ask IT to check which program tried. DNS answer only: no connection was seen; ask IT to check. |
| N2 | `known_bad_destination` | `blocklist_host_query` | The PC looked up a listed host name; ask IT support to check which program did so. |
| N3 | `phishing_domain_lookup` | `indicator_store_domain_match` | The PC looked up a domain already in an ETIS incident; if you entered a password on it, change that password from a known-good device. |
| N4 | `phishing_domain_lookup` | `url_model_domain_high` | `analyst`: a model-only signal on a domain name; review it together with the related findings before acting. |
| N5 | `suspicious_domain` | `dga_like_domain`, `dga_nxdomain_burst` | Single name: `analyst` review. Burst: ask IT support to scan the PC, because a program may be trying generated domains. |
| N6 | `beaconing` | `periodic_beaconing` | Regular contact with one destination; ask IT support to check which program it is. Do not uninstall software on your own. |
| N7 | `unusual_port` | `unusual_remote_port` | `analyst`: check the program and the destination port against what the PC is expected to run. |
| N8 | `dns_tunnelling_signs` | `dns_long_labels`, `dns_high_entropy_labels`, `dns_txt_burst`, `dns_very_long_name` | `analyst`: DNS traffic that may carry data; check the program responsible. |
| N9 | `rare_destination` | `rare_first_seen_destination` | `analyst`, informational: context for the other findings only. |

A test (§6, step 5) asserts complete coverage for every registered engine. For phishing,
the test also replays the existing endpoint and probe fixtures and checks that every
emitted reason is in the declared set.

### 2.3 Selection per Finding

A pure function, `recommended_actions(finding) -> list[Action]`:

1. Order the Finding's reasons. The order of `evidence.reasons` cannot be used for every
   engine: phishing puts the decisive reason first, but `network.windows` sorts its reasons
   alphabetically (`sorted(alert.reasons)`, **verified** in `engine.py`). So each catalogue
   entry has a fixed integer `rank`, where lower means more urgent. Reasons are ordered by
   `rank`, ties keep their `evidence.reasons` order, and for `phishing.analyze` the decisive
   reason (`evidence.reasons[0]`) always comes first.
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
  `GET /incidents/{id}` and `GET /device-risk/detail`, and through `GET /recommended-actions`
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

A device has two references. Only the second is ever stored.

1. **Endpoint ref (`hmac:`), computed where the logs or files are read.** This is the
   existing host pseudonym, `Pseudonymizer(ETIS_HOST_PSEUDONYM_KEY).host_ref(name)` =
   `'hmac:' + HMAC-SHA-256(key, 'host\0' + name.casefold().split('.')[0])[:32 hex]`
   (**verified** in `backend/app/engines/host/pseudonyms.py`). `network.windows` already
   uses the same function (**verified** in `backend/app/engines/network_windows/devices.py`).
   The agent sends this form, and the agent's batch check validates it.
2. **Stored ref (`srv:`), computed on the server before any storage** (owner decision Q13,
   27 November 2026): `'srv:' + HMAC-SHA-256(ETIS_SERVER_REF_KEY, 'device\0' + endpoint_ref)[:32 hex]`.
   That is 36 characters, which fits `String(37)`. `ETIS_SERVER_REF_KEY` is 32 random bytes,
   generated by `scripts/initialize.py` into the ignored `.env` of the machine that holds
   the database. It is never sent to an agent. A stolen company host key alone no longer
   lets anyone confirm a guessed computer name against the server's stored refs.
   **Account refs** are wrapped the same way, with their own purpose string (owner decision
   Q19, matching the owner's answer to agent §11 question 1):
   `'srv:' + HMAC-SHA-256(ETIS_SERVER_REF_KEY, 'account\0' + endpoint_account_ref)[:32 hex]`.
   The purpose strings keep a device ref and an account ref apart even if their inputs were
   equal. Well-known service principals (`sid:S-1-5-18`, `-19`, `-20`, **verified** in
   `pseudonyms.py`) stay as they are, because they identify no person and analysts need to
   read them.

**Key lifetime.** Rotating or losing `ETIS_SERVER_REF_KEY` changes every stored ref from
then on. Old and new refs cannot be joined, so one PC or account would appear as two, and
its device score and history would split. Rotation is **out of scope for v2**, and no rotate
command is designed. `scripts/initialize.py` generates the key only when `.env` has none, and
**never overwrites an existing key**. The key must be backed up with the database: a database
restored without its key keeps its old refs, but new findings from the same PC would get
new, unjoinable refs.

**One name, one ref (owner decision Q17).** A shared helper,
`app/core/device_names.py::local_device_name(raw) -> str | None`, returns the text before
the first dot, stripped and lower-cased, or `None` when that is empty. It is applied alike to
`socket.gethostname()`, `COMPUTERNAME`, `--device-name` and the EVTX `Computer` field, in
the agent, `scan_files.py`, `import_network_windows.py` and the host import. `host_ref`
still applies `casefold()` afterwards, which leaves an ASCII lower-case name unchanged. The
helper makes case and domain suffix consistent. It cannot repair a NetBIOS name that
Windows truncated (V12), so the design also fixes one source order for "this PC": first
`socket.gethostname()`, then `COMPUTERNAME`, then `platform.node()`. This reverses
`network.windows`'s current default (`COMPUTERNAME` first, **verified** in
`devices.py::default_device_name`). It is a naming change only; no detection rule changes.

| Engine | Endpoint ref in `evidence.details` |
| --- | --- |
| `network.windows` | `device_ref`, set by the engine (**verified**, `engine.py` details). The name comes through `local_device_name()`. |
| `host.windows` | `host_ref`, set by the engine from the EVTX `Computer` field once it emits Findings, through `local_device_name()`. |
| `malware.files` | `device_ref`, injected after the engine runs, by the agent wrapper (windows-agent-lan-v1 §1.1, step 5) and **also by standalone `scan_files.py`** (owner decision Q16). Both use the same helper, `app/core/device_names.py::attach_device_ref(finding, host_key)`, so there is one path. The malware engine and its frozen rule stay unchanged. If the host key is missing, the scan still runs and its findings have no device. |
| `network.flows` (Zeek, paused) | Not attributed. Its `local_host_ref` uses a different key (`ETIS_NETWORK_PSEUDONYM_KEY`), so it cannot be joined. |
| `phishing.analyze`, provider, e-mail and BEC rules | Not attributed. A submitted message describes a person's inbox, not a device. These findings are listed on the console as "not tied to a device". |

**Wrapping happens in one place.** `record_findings` is the single choke point for every
ingestion path: agent batches, standalone imports and scans on the server, and any future
path. As its first step it calls `wrap_refs(finding)`:

- it reads `details.device_ref`, `details.host_ref` and `details.account_ref`, accepting
  only `^hmac:[0-9a-f]{32}$`, and for `account_ref` also the well-known `sid:` forms;
- it rejects a Finding that already carries `srv:` in any of them, with
  `ref_prefix_invalid`, because only the server makes that form;
- if `device_ref` and `host_ref` are both present and differ, it rejects the Finding with
  `device_ref_conflict`, logged without the values;
- it replaces each `hmac:` field with its `srv:` form (device purpose for `device_ref` and
  `host_ref`, account purpose for `account_ref`). The Finding is frozen, so it builds a copy
  with `model_copy`;
- if `ETIS_SERVER_REF_KEY` is missing, it removes those fields instead, so the Finding is
  stored without a device or account ref, and logs `server_ref_key_missing` once per call.
  An `hmac:` ref is never stored as a fallback.

Only then are the Finding and `finding_devices` written. No `hmac:` device or account ref is
ever stored, so one PC (or account) has one ref whatever path its findings took. Malware
`path_ref` is not wrapped: it is a per-device file pseudonym under a key that stays on the
endpoint, and it never joins across PCs.

**Storage.** A new table, `finding_devices(finding_id PK/FK → findings ON DELETE CASCADE,
device_ref String(37) always 'srv:…', attributed_by String(32))`, where `attributed_by` is
`engine_details` or `agent`, is filled by `record_findings` (migration
**`009_finding_devices`**; `008` is `008_network_windows_imports`).

**Refs stored before v2** (owner decision Q20). Earlier `network.windows` imports and any
other findings stored with `hmac:` refs are converted by a one-off command,
`data/scripts/rewrap_device_refs.py`, delivered in step 7b. It is run once after
`initialize.py` has the server key. Migration `009` cannot do this, because a migration must
not need a secret. The command:

- rewrites `details.device_ref`, `host_ref` and `account_ref` from `hmac:` to `srv:` with
  the same `wrap_refs` function;
- fills `finding_devices` for the rewritten findings;
- leaves values that are already `srv:` or `sid:` unchanged, so a second run changes
  nothing;
- prints only counts;
- refuses to run without the server key.

The Finding schema
(`finding-v1`) does not change. Malware findings recorded before v2 carry no device ref at
all and stay unattributed (open question Q8). Device pseudonyms still never pivot incidents (host-engine-v1 §6.6,
windows-agent-lan-v1 §6).

**Label.** For an agent-paired device, the console shows the agent's operator-set
`devices.display_label` (pattern `^[A-Za-z0-9_.-]{1,64}$`, windows-agent-lan-v1 §5.3).
This answers the former Q9. A device seen only through standalone imports has no label and
is shown by its short stored ref (`srv:3f9a…`).

### 3.3 Inputs

For one `device_ref`, the score uses every Finding attributed to it with `observed_at`
inside the **score window** at read time, **except** findings whose incident is resolved
`false_positive` or `benign`. Excluded findings are still listed, with the reason. For each
finding it reads only `engine_name`, `domain`, `kind`, `severity`, `confidence`,
`observed_at` and the incident's resolution. No evidence detail or indicator value is used.

**Score window.** Findings live only as long as their engine's retention setting allows, and
the agent design adds no setting of its own: `ETIS_AGENT_RETENTION_DAYS` does not exist
([windows-agent-lan-v1](windows-agent-lan-v1.md) §7.3, owner decision Q2 there). Agent
`sensor` Findings and standalone imports expire under the same per-engine settings:

| Engine | Retention setting (default) | State in code |
| --- | --- | --- |
| `malware.files` | `ETIS_MALWARE_RETENTION_DAYS` (30) | exists (`settings.malware_retention_days`) |
| `network.windows` | `ETIS_NETWORK_RETENTION_DAYS` (30) | exists (`settings.network_retention_days`) |
| `host.windows` | `ETIS_HOST_RETENTION_DAYS` (30) | named by host-engine-v1 §7 and the agent design; added with the host engine. Until then the host window is 30 days. |

The score window is therefore **min(30, each contributing engine's retention)** days. Each
engine's findings are read only inside its own window, `min(30, that engine's retention)`.
The step 2 recency halves (0–7 and 8–30 days) apply inside it. A window shorter than 7 days
leaves no half-weight period. The Risk panel states each engine's window (§3.5).

**Revoked devices.** Findings from a device whose agent token was revoked, and that the
operator has not purged, **still count** (windows-agent-lan-v1 §4.1 and §5.3, owner decision
Q3 there). Revoking stops new submissions; it does not make earlier evidence untrue. Purging
is an explicit operator action (`POST /devices/{id}/purge-findings`), never automatic, and
purged findings are simply gone from the inputs. Once `010_agent_devices` lands,
`/device-risk/detail` joins `devices.status` on the `srv:` `device_ref` and marks every
contribution row of a revoked device **"from a revoked device"**. Until then no device can be
revoked, so the join is absent and nothing is marked.

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
rounded up. Findings outside their engine's window (§3.3) are not inputs.

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

The number is shown next to the band. **The points table, the 7/30-day windows, the +3/+6
term and the band edges are accepted for v1 as design choices, not fitted values** (owner
decision, 27 November 2026, was Q10). They were not tuned on any data, and the console text
(§3.5) says so. Changing any of them is a new version (`device-risk-v2`) with a dated note,
as for other ETIS rules.

Ceilings per engine today (**verified** in the engine code): `network.windows` never emits
`confirmed`, and N9 is always `info`, so it scores 0. `malware.files` emits `high` at most,
with `corroborated`, `single_signal` or `undetermined`. Neither engine reaches `critical`.
A single network or malware finding therefore scores at most 5 points.

**Worked example (invented).** A PC has these findings:

| Finding | Severity, confidence, age | Points |
| --- | --- | --- |
| `malware.files` `known_bad_hash` | high, corroborated, 2 days | 5 |
| `malware.files` `known_bad_hash` | same kind again, 3 days | repeat, not counted |
| `network.windows` `beaconing` (N6 combined with an N1 list hit) | high, corroborated, 1 day | 5 |
| Cross-engine term: one additional domain (network) with ≥ 3 points in 7 days | | +3 |

The total is **13 → high**. If the beaconing incident were resolved `benign`, the total
would be 5 → elevated, and the beaconing line would show "excluded — incident resolved
benign".

### 3.5 Explanation shown to the user

The score appears in the **Devices** tab (`/devices`). The agent design also defines that
tab and `GET /devices`, `GET /devices/{id}` (windows-agent-lan-v1 §5.3, §7.2), so core v2
does not add a second one. Whichever design is implemented first creates the tab, and the
other extends it (§3.6). The device list gains a band chip and a points column and is
sortable by them. Devices seen only through standalone imports (in `finding_devices` but not
in the agent's `devices` table) are listed too, marked "not paired". The device detail gains
a **Risk** panel:

1. **The total line.** For example: "13 points — high. Computed now from findings of the
   last 30 days (`device-risk-v1`)." Below it, **each engine's window**, for example
   "malware 30 days · network 14 days (`ETIS_NETWORK_RETENTION_DAYS`) · host 30 days", so a
   shortened retention is visible rather than silent (§3.3).
2. **A contribution table** with one row per counted finding: engine, kind, severity,
   confidence, age, points before and after recency, a link to its incident, and its primary
   recommended action (§2).
3. **The cross-engine line**, for example: "+3 — malware and network findings on this device
   in the same week".
4. **Not counted:** repeats, findings outside their engine's window (count only) and
   excluded findings, each with its reason. A row from a revoked device stays counted and
   carries the badge "from a revoked device" (§3.3).
5. **A fixed "What this score is" text** (AR/EN, reviewed like §2.1): "A count of what ETIS
   engines reported on this device recently, weighted by severity and confidence. It is not
   a probability that the device is compromised, it does not include checks ETIS did not
   run, and a score of 0 does not mean the device is safe. Its weights are fixed design
   choices, not fitted to data. A device that is itself compromised can report false
   findings about itself."

The API endpoints are `GET /device-risk` (all devices with attributed findings: `device_ref`,
band, points, last finding) and `GET /device-risk/detail?device_ref=srv:…` (the panel
above). They are kept apart from the agent's `/devices/{id}`, which is keyed by the agent's
integer device id and covers pairing state. Both are read-only, require `verify_api_key`,
appear in the proxy allowlist, accept **only** `^srv:[0-9a-f]{32}$` (an `hmac:` value is rejected with `invalid_input`), and
return `database_unavailable` without echoing input.

### 3.6 Fit with the Windows agent's `device_ref` (FR-11)

Read from [windows-agent-lan-v1](windows-agent-lan-v1.md) **agent-design-v1.1**, on branch
`origin/feat/agent-design-v1.1` at `fbeeec5`, read with `git show` on 28 November 2026 and not yet
merged into `main`. The first version merged at `bf67aae` is superseded by it.

| Point | Agent design | Core v2 | Fit |
| --- | --- | --- | --- |
| Value and format | Endpoint computes `device_ref = Pseudonymizer(host_key).host_ref(socket.gethostname())` with the company key received at pairing; `hmac:<32 hex>`, `String(37)` (§1.3, §7.1). | The endpoint sends `hmac:`; the server stores only `srv:<32 hex>` (36 characters, fits `String(37)`) (§3.2). | Fits after the agent changes below. |
| Binding | Server rejects a batch whose Finding `details.device_ref` / `host_ref` differs from the token-bound `devices.device_ref` (`422 device_ref_mismatch`, §5.2). | Unchanged in meaning. The check validates the incoming `hmac:` format, computes its `srv:` wrap, and compares that with the stored `devices.device_ref` (`srv:`) using `hmac.compare_digest`. The batch is accepted or rejected **before** anything is stored, and no `hmac:` value is kept. | Fits, with the agent change below. |
| Malware | Agent injects `device_ref` into malware `evidence.details`. | Standalone `scan_files.py` does the same through the shared `attach_device_ref` helper (Q16). `attributed_by = agent` when the Finding's `source_ref` starts with `agent_devices:`, else `engine_details`. | Fits. One path. |
| Server-side re-wrap | Agent §11 question 1 (open there). | **Adopted** (owner decision Q13): `srv:HMAC(ETIS_SERVER_REF_KEY, endpoint_ref)`, applied in `record_findings` (and at pairing) before any storage, on every ingestion path including standalone imports on the server. Stored refs are always `srv:`, and `/device-risk` accepts `srv:` only. | Fits after the agent changes below. |
| Host name source | Agent uses `socket.gethostname()`. | One shared helper, `local_device_name()` (owner decision Q17), applied to `gethostname()`, `COMPUTERNAME`, `--device-name` and the EVTX `Computer` field. Source order for "this PC": `gethostname()`, then `COMPUTERNAME`, then `platform.node()` (§3.2). | Fits. Residual risk: an EVTX `Computer` value or an operator-typed `--device-name` that is a truncated NetBIOS name still differs (V12). |
| Migration number | Agent plans `009_agent_devices` "or next free number" (§7.1). | `009_finding_devices` (owner decision). | **Conflict, resolved by the owner's numbering:** the agent migration moves to `010` (or the next free number when it lands), and its "upgrade from `008`" test becomes "from `009`". |
| Console | `/devices` tab and `/devices/{id}` detail. | Risk panel inside that tab; separate `/device-risk` API (§3.5). | Fits, once the tab ownership in §3.5 is followed. |
| Retention | No agent setting (`ETIS_AGENT_RETENTION_DAYS` removed). Agent Findings expire under the per-engine settings `ETIS_HOST_RETENTION_DAYS`, `ETIS_MALWARE_RETENTION_DAYS` and `ETIS_NETWORK_RETENTION_DAYS`, each defaulting to 30 (§7.3). | Score window = min(30, each engine's retention); the Risk panel states each engine's window (§3.3, §3.5). | Fits. |
| Revoked device | Existing Findings are kept and marked "from a revoked device" (`device_revoked: true`); an optional, never-automatic purge deletes them on or after a chosen time (§4.1, §5.3, Q3). | Unpurged findings from a revoked device still count. Once `010_agent_devices` lands, `/device-risk/detail` joins `devices.status` and marks them "from a revoked device" (§3.3). | Fits. |
| Compromised endpoint | It can fabricate findings for its own `device_ref` (§2 A4). | Its own score can be raised or padded; no other device's score is affected, because scores are per device and repeats do not add (§3.4 step 3). | Fits. Stated as a limit in the "What this score is" text. |

**Agent changes: applied.** The seven changes this section asked of the agent design are now
applied in `windows-agent-lan-v1.md` (agent-design-v1.1, §1.3, §2, §4.1, §5.2, §5.3, §7.1,
§10, §11.1):

1. migration `010_agent_devices`, with its upgrade test starting from `009`;
2. `devices.device_ref` stores only `srv:`; pairing validates the wire `hmac:`, wraps it with
   `wrap_ref(ref, "device")` and does not echo a `device_ref`;
3. the batch check compares `wrap_ref(incoming hmac:)` with the stored `srv:` value, and only
   `hmac:` is accepted on the wire;
4. `ETIS_SERVER_REF_KEY` is generated on the server only when absent, never sent to an
   agent, and listed in the threat model; rotation is out of scope;
5. the agent runner uses `local_device_name()` and `attach_device_ref()` from
   `app/core/device_names.py`;
6. console and API show and accept `srv:` refs only, for devices and accounts;
7. agent §11 question 1 is answered for `device_ref`, `host_ref` and `account_ref`, all
   wrapped at the single wrap point in `record_findings`.

They take effect in `main` when `feat/agent-design-v1.1` is merged.

## 4. De-fanged indicators everywhere in the console

### 4.1 Principle

Storage, hashing, lookups, correlation, STIX patterns and STIX ids keep **canonical**
values. De-fanging is applied only where a person reads or copies a value: the console and
the human-readable `note` of a STIX bundle (§1.5). `InertValue` stays non-clickable and
left-to-right. De-fanging adds protection against auto-linking by browsers, chat tools and
e-mail clients when the text is copied, and against accidental clicks or pastes.

### 4.2 Rules (`defang-v1`)

| Type | Canonical | Displayed |
| --- | --- | --- |
| `url` | `https://evil.example/a.php?x=1` | `hxxps://evil[.]example/a.php?x=1`. The scheme becomes `http`→`hxxp`, `https`→`hxxps`, `ftp`→`fxp`. Every `.` in the **host** becomes `[.]`; path, query and fragment are unchanged. A `@` in userinfo becomes `[@]`, and `:` before a port stays. Also (owner decision, §7.1.1 D4): dots in userinfo are de-fanged too (`https://bank.example@evil.example/` → `hxxps://bank[.]example[@]evil[.]example/`); an IPv4 host in a URL gets **every** dot de-fanged, like any host (`hxxp://203[.]0[.]113[.]7:8080/x`); the colons inside an IPv6 host become `[:]` (`hxxp://[2001[:]db8[:][:]1]/x`). |
| `domain` | `evil.example` | `evil[.]example`. IDN hosts are shown in their stored IDNA ASCII (`xn--…`) form, never as Unicode, so lookalike characters are visible. |
| `ip` | `203.0.113.7` / `2001:db8::1` | `203.0.113[.]7` (last dot only, the common convention) / `2001[:]db8[:][:]1` |
| `email` | `payroll@evil.example` | `payroll[@]evil[.]example` |
| `phone` | `+2010…` | Unchanged. The console page sets `<meta name="format-detection" content="telephone=no">` so mobile browsers do not turn numbers into call links (**to verify**, V8). |
| `hash`, pseudonyms | — | Unchanged. |

De-fanging is idempotent: an already de-fanged value is left as is. The rules are a fixed
table, `defang-v1`, committed as `docs/design/defang-cases.json` (input type, canonical,
displayed) and used by both implementations below.

### 4.3 Implementations

- **Backend:** `app/core/defang.py::defang(type, value)`, used only for the STIX bundle's
  human-readable `note`. The existing `extract_links` refang rule (`hxxp`→`http`, `[.]`→`.`) stays in
  `url_utils.py` and is not changed.
- **Frontend:** `src/api/defang.ts`, and a component
  `<IndicatorValue type value />` that wraps `InertValue` and always de-fangs. `InertValue`
  remains for non-indicator text (commands, model ids, the MITRE reference URL, `path_ref`).
- **Copy:** the copy button next to an indicator copies the de-fanged form.
- **Search input:** the Indicators page accepts both forms. The backend lookup refangs input
  with `app.core.defang.refang` before `normalize`, so `hxxps://evil[.]example` and
  `https://evil.example` hit the same `value_hash`. `refang` is a superset of the
  `extract_links` rule, which handles only `hxxp` and `[.]`: it also undoes `fxp`, `[@]` and
  `[:]`, so de-fanged e-mail and IPv6 values match too (owner decision, §7.1.1 D3).
  `extract_links` itself is unchanged.

### 4.4 Places changed

| Page / component | Value | Today |
| --- | --- | --- |
| `IncidentsPage.tsx` (indicator list) | `value` (feed/analyst) | `InertValue`, plain |
| `IndicatorsPage.tsx` (detail, registered domain, community reports) | `value`, `registered_domain`, `reported_value` | `InertValue`, plain |
| `ThreatFeedPage.tsx` | feed `domain` | monospace cell, plain |
| `ScanPage.tsx` (checked links) | `link.host` | monospace span, plain. The `/analyze` response itself is unchanged; de-fanging happens only in the page. |
| Devices tab Risk panel (§3.5) | none (pseudonyms only) | — |
| Agent device timeline (windows-agent-lan-v1 §7.2), when built | any indicator value shown | must use `IndicatorValue` from the start |

A static test (§6, step 9) fails if a page passes an indicator field (`value`, `host`,
`domain`, `registered_domain`, `reported_value`) to `InertValue` or renders it directly
instead of using `IndicatorValue`.

## 5. Data and API changes summary

| Change | Kind |
| --- | --- |
| `finding_devices` table | Migration **`009_finding_devices`**, after `008_network_windows_imports` (explicit `op.create_table`, fresh-vs-upgrade comparison as in core v1 §7.2). Downgrade drops it, and attributions can be rebuilt only for engines that keep the ref in details. The agent's `devices` migration takes the next free number (§3.6). |
| `ETIS_STIX_NAMESPACE`, `ETIS_SERVER_REF_KEY`, `ETIS_SHOW_DRAFT_ACTIONS` | Settings. The namespace and the server ref key are generated by `scripts/initialize.py` into ignored `.env` only when absent; an existing value is never overwritten. The server ref key is never sent to an agent, and rotation is out of scope (§3.2). |
| `app/core/device_names.py` (`local_device_name`, `attach_device_ref`, `wrap_ref`, `wrap_refs`) | Shared helpers for the agent, the standalone commands and `record_findings` (§3.2). `network_windows/devices.py::default_device_name` switches to them; the source order becomes `gethostname()` first. |
| `GET /device-risk`, `GET /device-risk/detail`, `GET /recommended-actions`; `recommended_actions` added inside `GET /incidents/{id}` finding rows | API additions documented in `docs/api-v2.md`. `/analyze` unchanged. `/devices/*` belongs to the agent design. |
| `recommended-actions-v1.json`, `defang-cases.json`, STIX schema subset, `EXPORTABLE_SOURCES` | Committed, reviewed files and constants. |
| `REASON_CODES` constant per engine module that lacks one | Declaration only. `network.windows` already has `detections.REASONS`. |

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
| 4 | `feat: offline STIX export command` | `data/scripts/export_stix.py`, `ETIS_STIX_NAMESPACE` in initialize, default `var/exports/` | `pytest backend/tests/test_stix_export.py -k "command or privacy or scope or licence"`: invented incidents with indicators from every source of §1.4. Analyst, confirmed-community and invented CC0-list values are exported with **real** values in their patterns. OpenPhish-, PhishTank-, scan-derived and malware-hash values are counted and never appear: a marker-string test covers patterns, ids, `note` and `x_etis_*`. Q14: a `manual` value whose `url_hash` is in `feed_observations`, `blacklist_entries` or a snapshot payload for `openphish` / `phishtank` (including an expired or rolled-back record), or whose domain equals such an entry's domain, is counted as `restricted_feed_overlap`. So is an `analyst` sighting with declared source `openphish` or `phishtank`; with `own_investigation` and no overlap it is exported. Feed tables are byte-identical before and after export. Q15: a confirmed community value without `licence_accepted = 'CC0-1.0'` is counted as `community_licence_not_accepted`, and with it, it is exported. Q18: a CC0-accepted community value that also appears in a stored OpenPhish or PhishTank record is counted as `restricted_feed_overlap`. A list file whose lock hash does not match is not used, and its IPs are counted as `list_not_installed`. `EXPORTABLE_SOURCES` is pinned. No hash-only `value_hash` appears in the output. No notes, pseudonyms or details appear. The `note` lists the exported values de-fanged, and patterns are never de-fanged. Resolved-benign incidents are excluded by default. The command refuses to overwrite and prints no values. With `socket.socket` patched to raise, the export still succeeds. Bytes are deterministic apart from the bundle id and timestamp. The ATT&CK notice is present when an attack pattern is exported. |
| 5 | `feat: recommended-actions-v1 catalogue and schema` | JSON catalogue with `rank`, including the 15 `network.windows` codes (§2.2); loader with strict schema; `REASON_CODES` declarations where missing | `pytest backend/tests/test_recommended_actions.py -k "schema or coverage"`: extra field rejected; URL/e-mail/phone regex rejects a text; both languages present; coverage for every registered engine's codes, using `network_windows.detections.REASONS` directly; phishing replay-fixture reasons ⊆ declared set. |
| 6 | `feat: recommended action selection per finding` | Pure `recommended_actions(finding)`, `recommended_actions` in incident detail, `GET /recommended-actions` | `pytest backend/tests/test_recommended_actions.py -k selection` and `pytest backend/tests/test_soc_api.py -k incident`: phishing decisive reason first; `rank` order for an alphabetically sorted `network.windows` reason list (e.g. N1 `blocklist_ip_connection` with `blocklist_ip_dns_answer`); at most 3 actions, de-duplicated; kind default; fallback, so every Finding gets an action (FR-14); draft hidden unless the flag is set; no endpoint with a write method under `/recommended-actions`. |
| 7a | `feat: shared device names and server-side ref wrap` | `app/core/device_names.py`; `ETIS_SERVER_REF_KEY` in initialize; `network_windows/devices.py` uses `local_device_name()` | `pytest backend/tests/test_device_names.py`: `local_device_name` gives the same result for `PC-01`, `pc-01.corp.example`, `PC-01.` and ` pc-01 ` (EVTX `Computer`, `COMPUTERNAME` and `gethostname()` shapes); empty → `None`; source order `gethostname()` → `COMPUTERNAME` → `platform.node()`; `wrap_ref` is deterministic, gives `srv:` + 32 hex (36 characters), differs under another server key and between the `device` and `account` purposes for the same input, rejects input that is not `hmac:`, and leaves a well-known `sid:` account ref unchanged; a missing or short `ETIS_SERVER_REF_KEY` raises a fixed reason code; `initialize.py` creates the key when `.env` has none and leaves an existing key byte-identical on a second run (isolated temporary `.env`). `pytest backend/tests/test_network_windows_devices.py` for the default-name change. |
| 7b | `feat: device attribution for findings` | Migration **009**, `finding_devices`, `record_findings` wraps device and account refs then attributes, `scan_files.py` attaches `device_ref` through `attach_device_ref`, one-off `data/scripts/rewrap_device_refs.py` (Q20) | `pytest backend/tests/test_core_migrations.py -k 009`: fresh-vs-upgrade schema equality from `008`. `pytest backend/tests/test_correlation.py -k device`: a `network.windows` finding is stored with `srv:` in both `details.device_ref` and `finding_devices`; no `hmac:` device or account ref appears in any stored row (marker test over `findings.evidence` and `finding_devices`); a `network.windows` Sysmon finding stores `account_ref` as `srv:` and a `sid:S-1-5-18` account ref unchanged; a Finding arriving with `srv:` in any ref is rejected (`ref_prefix_invalid`); a missing server key stores the Finding without device or account refs; differing `device_ref`/`host_ref` → `device_ref_conflict` logged without values; an agent-shaped malware finding (`source_ref` `agent_devices:…`) is attributed as `agent`; the same PC through a standalone import and an agent-shaped batch gets **one** `srv:` ref; device refs never create or join incidents. `pytest backend/tests/test_malware_scan_command.py -k device`: the standalone scan attaches the endpoint ref, stored as `srv:`; a missing host key → no device while the scan still succeeds. `pytest backend/tests/test_rewrap_device_refs.py`: invented findings stored with `hmac:` refs are rewritten to `srv:` and get `finding_devices` rows; **a second run changes nothing** (row-by-row equality of `findings.evidence` and `finding_devices` before and after); refuses without the server key; prints counts only. `/analyze` gate: `test_findings_parity.py`, targeted. |
| 8 | `feat: device-risk-v1 score and device-risk API` | Pure `device_risk(findings, now)`, `/device-risk` routers | `pytest backend/tests/test_device_risk.py`: every cell of the points table; recency boundaries at 7/8 and 30/31 days; repeat rule; cross-engine +3 and +6 cap, not given for a domain below 3 points or older than 7 days; resolved benign/false positive excluded and listed; the worked example of §3.4 gives 13 → high; band edges 0/1/4/5/9/10; N9 `info` scores 0; each engine's window is min(30, its retention setting) and is reported per engine; findings from a revoked device still count (the "from a revoked device" mark is tested once `010_agent_devices` exists). `pytest backend/tests/test_soc_api.py -k device_risk`: auth; `srv:` accepted, `hmac:` and other forms rejected with `invalid_input`; no echo; read-only. |
| 9 | `feat: de-fanged indicator display in the console` | `defang.ts`, `IndicatorValue`, pages of §4.4, `format-detection` meta, copy button | `node --experimental-strip-types --test etis-frontend/tests/defang.test.mts` over `defang-cases.json` (Node 22.12 is installed; the flag is **to verify**, V9); static check script for raw indicator rendering; frontend build and `oxlint` on changed files. |
| 10 | `feat: recommended actions and device risk in the console` | Incident detail actions; Devices tab with Risk panel (created here, or added to the agent's tab if that has landed, §3.5); i18n keys AR/EN; proxy allowlist for `/api/device-risk*` and `/api/recommended-actions` | Frontend build, `oxlint`, an i18n key parity check (every new key in both `ar.json` and `en.json`), `pytest backend/tests/test_proxy_routes.py` for the allowlist; manual RTL and 390-pixel check as recorded today. |
| 11 | `docs: core v2 implementation notes` | README / LOCAL-IMPLEMENTATION status, `docs/api-v2.md`, `docs/engine-authors.md` (declare `REASON_CODES`, add catalogue entries, set device ref) | none (docs only) |

Release check before the action feature is shown by default: every catalogue entry is
`reviewed` by the team member the owner names before release (§2.1). Until then, draft
actions stay hidden.

Run constraint for this design session (27 November 2026): no tests and no Python were run,
because a memory-heavy training run was active on this PC. Only git and file edits were
made.

## 7. Decisions and open questions

### 7.1 Owner decisions (27 November 2026)

| # | Decision | Where applied |
| --- | --- | --- |
| Q1 | Patterns hold real values so that machines can match them. De-fanging applies only in the console and in the bundle's human-readable `note`. | §1.5, §4.1 |
| — | Licence filter: export only values from analyst, community and the CC0 abuse.ch Feodo Tracker list. OpenPhish and PhishTank values are never exported, only counted. | §1.4 |
| — | `network.windows` is in scope: its N1–N9 codes go into the action catalogue, and its host pseudonym is used for device attribution. | §2.2, §3.2 |
| — | The core v2 migration is `009_finding_devices`. | §3.2, §5, §6 |
| Q9 | Device labels come from the agent's `display_label` (resolved by the agent design, not by a separate core v2 label). | §3.2 |
| Q10 | The device-risk weights are accepted for v1 and labelled as design choices, not fitted. | §3.4, §3.5 |
| Q11 | FR-11 to FR-14 wording recorded. | Header |
| Q12 | The reviewer is a team member named by the owner before release. Draft actions stay hidden until then. | §2.1, §6 |
| Q13 | Server-side re-wrap adopted: the server stores `srv:HMAC(server_key, endpoint_ref)`. The agent sends `hmac:` and the batch check validates `hmac:`. The wrap happens after the mismatch check and before any storage, on every ingestion path including standalone imports on the server. Stored refs are always `srv:`, and `/device-risk` accepts `srv:` only. The agent design needs this in its step 1 (§3.6 list). | §3.2, §3.5, §3.6, §6 step 7 |
| Q14 | An analyst-entered value is not exported if it also appears in any stored OpenPhish or PhishTank feed record, or if its declared source is one of them. | §1.4 rules |
| Q15 | Community values are not exported until the submission form states that they are shared under CC0 and the reporter accepts that. Until then they are counted only. | §1.4 table and rules |
| Q16 | `scan_files.py` attaches `device_ref` too, through the same helper as the agent. | §3.2, §3.6 |
| Q17 | One shared helper, `local_device_name()`: lower-case short name (text before the first dot), applied alike to `gethostname()`, `COMPUTERNAME` and the EVTX `Computer` field. V12 stays to verify. | §3.2, §3.6, §6 step 7a |
| — | The agent migration moves to `010`. | §3.6 |
| Q18 | The restricted-feed check also applies to community values. | §1.4 rules, §6 step 4 |
| Q19 | `account_ref` is wrapped with the server key too: same `srv:` form, same single wrap point in `record_findings`. This matches the owner's answer to agent §11 question 1 (device and account refs). | §3.2, §3.6, §6 step 7a/7b |
| Q20 | A one-off, idempotent `rewrap_device_refs.py` in step 7b converts refs stored before v2, with a test that a second run changes nothing. | §3.2, §6 step 7b |
| — | Rotating or losing `ETIS_SERVER_REF_KEY` changes every stored ref, and old and new refs cannot be joined. Rotation is out of scope for v2, and `initialize.py` never overwrites an existing key. | §3.2 (key lifetime), §3.6, §5 |

### 7.1.1 Owner decisions on implementation departures (28 November 2026)

| # | Decision | Where applied |
| --- | --- | --- |
| D1 | ATT&CK techniques are exported with an ETIS-namespace id, a `mitre-attack` external reference and MITRE's id in `x_etis_mitre_stix_id`. | §1.2, §1.6 |
| D2 | `--tlp` offers `white` instead of `clear`, with the help text "TLP:WHITE (STIX 2.1 built-in TLP 1.0 marking; TLP 2.0 calls it CLEAR)". The default stays AMBER. A TLP 2.0 extension is to verify later (V13). | §1.1, §1.2, Q3 |
| D3 | The indicator lookup uses the fuller `refang`, which also undoes `fxp`, `[@]` and `[:]`. | §4.3 |
| D4 | The extra de-fang cases are kept: userinfo dots, every dot of an IPv4 URL host, and IPv6 URL host colons. | §4.2, `defang-cases.json` |

### 7.2 Open questions

| # | Question | Default if unanswered |
| --- | --- | --- |
| Q2 | Should malware hash-list matches store and export the file's SHA-256? Such a hash is already public in the list, but the change touches the frozen malware engine and needs separate approval. | Not exported. |
| Q3 | Default TLP marking: AMBER (owner shares deliberately), GREEN or WHITE? Only the TLP 1.0 markings are built into STIX 2.1 (**verified**, V6). TLP 2.0 (CLEAR, AMBER+STRICT) would need an OASIS extension (V13). | TLP:AMBER (1.0, built in). |
| Q4 | Use the OASIS incident core extension instead of `x_etis_*` properties? | `x_etis_*`. |
| Q5 | Export campaigns (`campaign` SDO + `attributed-to`/`related-to`)? | Not in v2. |
| Q6 | May `stix2-validator` be a development-only dependency if it is offline and its licence fits? | No. Use the committed schema subset only. |
| Q7 | Show the recommended action on the scan page, through a separate lookup by decisive reason (the `/analyze` response stays unchanged)? | Not in v2. |
| Q8 | Back-attribute existing malware findings to this PC's device? Scans may have read files copied from elsewhere. | No. Only new scans are attributed. |

## 8. To verify (before the step that depends on it)

| # | Fact | Where to read | Step |
| --- | --- | --- | --- |
| V1 | **Verified 27 November 2026.** Required common properties `type`, `spec_version`, `id`, `created`, `modified` on SDOs and SROs; the bundle has no `spec_version` (spec §3.2 table, `core.json`). Required per type: identity `name`; incident `name`; indicator `pattern`, `pattern_type`, `valid_from`; sighting `sighting_of_ref`; relationship `relationship_type`, `source_ref`, `target_ref`; attack-pattern `name`; note `content`, `object_refs`. | Spec §3.2, §4.1–§4.13; `cti-stix2-json-schemas` | 3 |
| V2 | **Verified.** `defanged` exists on SCOs only (spec §3.2 table). Kept for reference; v2 exports no SCOs. | Spec §3.2 | — |
| V3 | **Verified.** There is no telephone observable. The 2.1 observable schemas are artifact, autonomous-system, directory, domain-name, email-addr, email-message, file, ipv4-addr, ipv6-addr, mac-addr, mutex, network-traffic, process, software, url, user-account, windows-registry-key and x509-certificate. `phone_number` and `phone_numbers` are reserved property names. | `cti-stix2-json-schemas/schemas/observables`, spec §3.8, `core.json` | 3 |
| V4 | **Verified.** `confidence` is an optional integer 0–100 (spec §3.2). | Spec §3.2 | 3 |
| V5 | Incident core extension: status, identifier and properties | OASIS CTI extension repository | Q4 only |
| V6 | **Verified** (schema and OASIS library; the spec §7.2 text was not reached). TLP 1.0 marking definitions: WHITE `613f2e26-407d-48c7-9eca-b8e91df99dc9`, GREEN `34098fce-860f-48ae-8e50-ebd3cc5e41da`, AMBER `f88d31f6-486f-44da-b317-01333bde0b82`, RED `5e57c739-391a-4eb3-b6be-7d15ca92d5ed` (each `marking-definition--…`), `created` `2017-01-20T00:00:00.000Z`, `definition_type` `tlp`. Vocabularies: `identity-class-ov` includes `system`, `indicator-type-ov` includes `malicious-activity`, and `pattern-type-ov` includes `stix`. Pattern string escaping doubles the backslash first, then turns `'` into `\'` (`escape_quotes_and_backslashes` in `cti-python-stix2`). The patterning grammar file itself was not found in the OASIS validator repository. | `cti-stix2-json-schemas/schemas/common/marking-definition.json`, `sdos/identity.json`, `sdos/indicator.json`; `cti-python-stix2` `stix2/v21/common.py`, `stix2/patterns.py` | 3 |
| V7 | `stix2-validator` licence and whether it runs fully offline | its PyPI page and repository | Q6 only |
| V8 | `format-detection` meta behaviour in current mobile Safari / Chrome | browser documentation | 9 |
| V9 | `node --experimental-strip-types --test` works on the installed Node 22.12 without extra packages | Node 22 documentation, local run | 9 |
| V10 | abuse.ch terms of use §3.4 still grant CC0 for Feodo Tracker and SSL Blacklist. **Verified 2026-11-27** (re-read before the network-windows step 5 fetch, `docs/data-licences.md`). The SSL Blacklist IP list was found deprecated on 2025-01-03 (its file header), so it was removed from the export sources; only Feodo Tracker remains. | https://abuse.ch/terms-of-use/ | 4 |
| V11 | OpenPhish and PhishTank current terms (both are excluded either way; re-read only to keep `docs/data-licences.md` current) | https://openphish.com/terms.html, https://phishtank.org/terms.php | — |
| V12 | The Windows NetBIOS computer name (`COMPUTERNAME`) is limited to 15 characters and may differ from the DNS host name returned by `socket.gethostname()` | Microsoft documentation on computer naming | 7a (Q17 residual risk) |
| V13 | Whether OASIS publishes a TLP 2.0 marking extension for STIX 2.1 (CLEAR, GREEN, AMBER, AMBER+STRICT, RED), and if so its extension-definition id, status and licence. This matters only if TLP 2.0 markings are wanted later; v2 uses TLP 1.0. | OASIS CTI common objects and extension repositories | later (Q3) |

## Sources

- [Core v1 design](core-v1.md): Finding schema, indicator plaintext rules (§2.3), unkeyed
  hash note (§2.2), categorical confidence (§1.1), stoplist and correlation (§3).
- [Host engine v1](host-engine-v1.md) §6.4, §6.6 and [network-windows v1](network-windows-v1.md)
  §6.5, §6.6: `host_ref`/`device_ref` definition and the rule that pseudonyms never pivot.
- [Malware engine v1](malware-engine-v1.md): hash-only file indicator, frozen v1 rule,
  `path_ref`.
- [Engine authors guide](../engine-authors.md): engine rules this design extends.
- [Windows agent and LAN server v1](windows-agent-lan-v1.md) §1.3, §5.2, §5.3, §7.1, §7.2,
  §11: endpoint `device_ref`, binding check, `devices` table and API, open re-wrap question.
- `backend/app/engines/network_windows/` (`detections.py` `REASONS`, `engine.py` `KINDS`,
  severity, confidence, details and indicators; `devices.py`), read on 27 November 2026.
- `docs/data-licences.md`: ATT&CK copyright statement required when ATT&CK names are shown
  or exported; `abuse_ch_network_blocklists`, `openphish` and `phishtank` entries.
- OASIS, *STIX Version 2.1*, OASIS Standard, 10 June 2021,
  https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html — not re-read for this
  document. Every STIX fact above is marked **to verify** (V1–V6).
