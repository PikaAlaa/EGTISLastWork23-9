# Host engine v1 (`host.windows`) — design

Status: **design only** (18 November 2026), branch `feat/host-design`. No code, no
dataset or rule download, no measurement accompany this document.

`host.windows` reads Windows event logs that a user exports from their own PC, applies
explainable detection rules locally, and emits `finding-v1` Findings through the core v1
path ([core v1](core-v1.md) §1, §8; [engine authors](../engine-authors.md)). It follows
the structure of the [network engine design](network-engine-v1.md). It never touches
`/analyze`, the phishing thresholds or any frozen model, and it needs neither Zeek nor WSL:
everything runs in Python on Windows.

## 0. Constraints

| Constraint | How this design keeps it |
| --- | --- |
| Free and local only | EVTX files are parsed by a free Python library; rules run in Python and in-memory SQLite. No SIEM, cloud or paid service. |
| Event content never stored, never leaves the PC | Events live only in memory during an import. The database stores counts, rule ids, record numbers, hashed indicators and keyed pseudonyms (§7). |
| Indicators are inert | Addresses, domains, URLs and file hashes are hashed and never contacted or looked up. |
| Phishing path unchanged | Separate engine and rules; the `/analyze` parity gate keeps running. |
| Data and rule licences | Evaluation data and Sigma rules stay under ignored directories; `docs/data-licences.md` gets entries before acquisition; Sigma attribution is kept (§2.2). |
| ATT&CK ids current | Every id is checked against the local, hash-verified v20.0 catalogue; revoked ids are remapped (§5.2). |
| Honest claims | Evaluation uses public lab samples and a team-built benign corpus. Results are exposed development evidence, not accuracy on Egyptian PCs. |

## 1. Input: Windows event logs exported by the user

### 1.1 Channels

| Channel | Required | Key events used |
| --- | --- | --- |
| `Security` | Yes | 4624 logon (LogonType, IpAddress), 4625 failed logon, 4740 lockout, 4720 account created, 4732/4728/4756 member added to a group, 4697 service installed, 4698 scheduled task created, 4719 audit policy changed, 1102 audit log cleared |
| `System` | Yes | 7045 service installed, 7040 service start type changed, 7036 service state, 104 log cleared |
| `Microsoft-Windows-PowerShell/Operational` | Yes | 4104 script block, 4103 module/pipeline |
| `Microsoft-Windows-Windows Defender/Operational` | Recommended | 5001 real-time protection disabled, 5010/5012 scanning disabled, 5007 configuration changed |
| `Microsoft-Windows-TaskScheduler/Operational` | Optional | 106 task registered |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | Optional | 1149 RDP authentication (source address) |
| `Microsoft-Windows-Sysmon/Operational` | Optional | 1 process creation (with `Hashes`), 3 network connection, 13 registry value set, 22 DNS query |

Many events are absent under Windows' default audit policy. For example, 4698 and 4697
need object-access and system auditing, and full 4104 logging needs script block logging.
Every import therefore produces a **coverage report**: channels present, the time span
covered and which detections could not run. A detection that could not run is shown as
"not visible", never as "nothing found".

### 1.2 How the user supplies it

The user exports logs themselves, for example with Event Viewer → *Save All Events As…*
(`.evtx`) or, from an administrator prompt, `wevtutil epl Security C:\exports\Security.evtx`.
Then:

```
python data/scripts/import_host.py --evtx C:\exports\Security.evtx C:\exports\System.evtx ...
                                    [--local-net 192.168.1.0/24]
```

Files are read in place and never copied. There is no browser upload in v1, and v1 does
not read the live event log either: reading live logs needs administrator rights and a
Windows API dependency. Limits: 2,000,000 events and 1 GB per import, enforced before
parsing where possible and fail-closed otherwise.

### 1.3 Parser library

| Library | Licence | Windows | Notes |
| --- | --- | --- | --- |
| `evtx` (PyPI; Rust-based bindings) | MIT | Wheels for Windows x86-64, CPython ≥ 3.10 | **Chosen.** Fast; yields each record as JSON or XML. No Windows ARM64 wheel. |
| `python-evtx` | Apache-2.0 | Pure Python | Fallback; slower. |

Version 0.15.0 of `evtx` was released on 2026-11-01. At implementation time ETIS pins an
exact version at least two weeks old in `requirements-runtime.txt`; the project's own
Python (3.12) is supported. A test asserts the parser is used only for reading local files.

### 1.4 Normalised event record (in memory only)

Each EVTX record becomes a flat dictionary: `Channel`, `Provider`, `EventID`,
`TimeCreated` (UTC ISO-8601), `EventRecordID`, `Computer` and every `EventData`/`UserData`
field under its own name (`TargetUserName`, `LogonType`, `IpAddress`, `ScriptBlockText`,
`ServiceName`, `ImagePath`, `CommandLine`, `Hashes`, `QueryName`, …). Field names follow
Windows' names, which are also the names Sigma rules use. Records are loaded into an
**in-memory** SQLite table for rule evaluation (§2.3) and discarded when the import ends.

## 2. Detections

### 2.1 Behaviour list (v1)

These target what most often hits Egyptian individuals and small businesses: password
guessing against exposed RDP, account takeover, malware or remote-access tools staged with
PowerShell, persistence through services and tasks, and hiding tracks by clearing logs or
disabling Defender.

| Id | Detection | Source | Logic (fixed constants) | ATT&CK v20.0 |
| --- | --- | --- | --- | --- |
| H1 | Failed-logon flood | ETIS-native | ≥ 20 events 4625 for one target account in 10 min | `T1110.001` Password Guessing |
| H2 | Password spraying | ETIS-native | One source address or workstation with 4625 for ≥ 10 distinct accounts in 10 min | `T1110.003` Password Spraying |
| H3 | New local account | ETIS-native | 4720 | `T1136.001` Local Account |
| H4 | Added to local Administrators | ETIS-native | 4732 with group SID `S-1-5-32-544` | `T1098.007` Additional Local or Domain Groups |
| H5 | Suspicious PowerShell | Sigma candidates | Rules on 4104/4103 (and Sysmon 1 command lines): encoded commands, download cradles, AMSI tampering | `T1059.001` PowerShell; `T1027.010` Command Obfuscation; `T1105` Ingress Tool Transfer, as each rule's tags say |
| H6 | New service | ETIS-native + Sigma | 7045 or 4697; Sigma candidates for suspicious image paths | `T1543.003` Windows Service |
| H7 | New scheduled task | ETIS-native + Sigma | 4698 or TaskScheduler 106; Sigma candidates for suspicious actions | `T1053.005` Scheduled Task |
| H8 | Audit log cleared / auditing disabled | ETIS-native | 1102 (Security) or 104 (System) → clearing; 4719 removing success/failure auditing → disabling | `T1685.005` Clear Windows Event Logs; `T1685.001` Disable or Modify Windows Event Log |
| H9 | RDP logon from outside | ETIS-native | 4624 LogonType 10 (or 1149) whose source is not local (§6.4) | `T1133` External Remote Services; `T1021.001` Remote Desktop Protocol |
| H10 | Defender disabled | ETIS-native + Sigma | Defender 5001/5010/5012; 7040/7036 for `WinDefend` disabled or stopped; Sysmon 13 setting `DisableAntiSpyware`/`DisableRealtimeMonitoring` to 1 | `T1685` Disable or Modify Tools |

Combinations raise severity or confidence but never create a separate kind (§6.2–6.3):
for example H3 then H4 for the same account, or H1/H2 then a successful 4624 or H9 from
the same source.

### 2.2 Sigma rules: licence and attribution

- SigmaHQ rules are licensed under the **Detection Rule License (DRL) 1.1**. Use,
  modification, redistribution and commercial use are allowed with conditions:
  - Sharing rules requires keeping the rule's `author` field, a link to the rule or rule set
    where reasonably practicable, and a DRL notice or link.
  - **Messages based on matches must retain the author identification** supplied in the rule.
- ETIS therefore stores, for every Sigma-based finding, `evidence.details.sigma`: rule `id`,
  `title`, `author`, `level`, `status`, release tag and rule path, and `license: DRL-1.1`.
  The console shows the author and source with every Sigma finding.
- Rules come from one pinned SigmaHQ release package (tag and SHA-256 recorded at
  download), stored under ignored `data/external/sigma/`. Rule files are not modified. No
  rule text is committed except the ids, paths and hashes in the shipped-rule manifest
  (§4.6). A `docs/data-licences.md` entry quotes the DRL conditions.

### 2.3 Evaluating Sigma locally without a SIEM

`pySigma` (**LGPL-2.1**) parses the rules. The SigmaHQ `pySigma-backend-sqlite`
(**LGPL-3.0**, Python ≥ 3.11) converts each rule into a SQLite `SELECT` over a table of
flattened events; it is the converter behind Zircolite. ETIS:

1. Loads normalised events (§1.4) into an **in-memory** SQLite table.
2. Converts each candidate rule with the pinned backend, using a Windows processing
   pipeline so each rule only sees its own channel and EventIDs. The pipeline package and
   its licence are confirmed when pinned.
3. Registers a `REGEXP` function (the backend needs one for `re` modifiers).
4. Runs the queries and keeps matching `EventRecordID`s.

Known backend limits are handled by exclusion, never by rewriting rules: a rule that fails
to convert, needs multi-field `value_count`, or names fields ETIS never produces is excluded
and counted. ETIS uses the libraries as unmodified dependencies installed with pip. Their
LGPL terms are recorded in `docs/data-licences.md`; `LICENSE` remains the team's decision.
GPL-licensed command-line tools such as Chainsaw and Hayabusa were considered and not
chosen, because they would add separately downloaded binaries.

Threshold behaviours (H1, H2) and the cross-event combinations are ETIS-native Python with
the constants above, so their logic is explicit and testable rather than spread across
correlation SQL.

## 3. Evaluation data

### 3.1 Comparison

| | EVTX-ATTACK-SAMPLES (sbousseaden) | OTRF Security-Datasets |
| --- | --- | --- |
| Licence | **GPL-3.0** | **MIT** (repository `LICENSE` file; the README text says GPL-3.0, but the licence file and project site say MIT) |
| Content | Over 200 real `.evtx` files produced by attack tools in a lab | Atomic and compound scenarios; Windows host logs as **JSON** exports, with YAML metadata |
| Format parity with user input | **Same as user input (EVTX)**, so the full parser → normaliser → rules path is exercised | JSON exports need a separate format adapter, so the EVTX parser is not exercised |
| ATT&CK labelling | Folders by **tactic**; technique mapping held outside the files (README links), so per-file technique labels must be derived | Per-scenario metadata describing the simulation; technique fields to be confirmed at acquisition |
| Size | About 200+ files; small (exact size measured at acquisition) | Many scenarios across platforms; Windows subset to be sized at acquisition |
| Known label problems | Labels are coarse (tactic folders, file names); files may mix benign background events with the attack | Lab VMs with background noise; metadata quality varies by scenario |

### 3.2 Choice: EVTX-ATTACK-SAMPLES, for an exposed evaluation

It exercises exactly the input path users will use (EVTX), with real attack-tool output.
Its labels are coarse. Before any measurement, the team writes a **per-file
expected-technique manifest** from file names, folders and the repository's published
mapping, records the source of each label, and freezes it with its SHA-256. Files whose
technique cannot be determined are excluded and counted.

Security-Datasets stays a possible later, separately frozen secondary check through a JSON
adapter. GPL-3.0 and MIT data both stay local under ignored `data/external/` and are never
committed. Nothing is downloaded by this design; acquisition (pinned commit and file hashes)
needs the owner's approval.

## 4. Frozen evaluation and selection rule

This section is the rule. Before any rule is run on any sample or benign log, it is copied
unchanged into `evaluation/reports/<date>-host-v1/selection_rule.md` with its SHA-256
recorded. Later changes are dated pre-result amendments citing the previous hash. This is
an **exposed development protocol**: the attack samples are public, the benign corpus is
team-built, and neither represents Egyptian users' PCs.

### 4.1 Decision: rules only, no ML component in v1

ML is **not a candidate** in v1:

- Public attack samples have no per-event labels; files mix attack and background events.
- No sizeable, labelled benign host-event corpus from the target population exists. A
  team-built corpus would teach a model the team's VM habits.
- Rules are explainable, carry ATT&CK tags and Sigma author attribution, and each can be
  tested on invented events.

ML is reconsidered only if a labelled benign and attack corpus becomes available, under a
new frozen rule.

### 4.2 Candidate pool (fixed)

- **Native:** H1–H4, H6–H10 native parts, with the constants in §2.1. Never tuned.
- **Sigma:** every rule in the pinned SigmaHQ release package that meets all of:
  - Windows log source ETIS can feed (§1.1);
  - `status` stable or test;
  - `level` medium, high or critical;
  - at least one ATT&CK technique tag that, after revocation remapping (§5.2), is in the §5
    target set;
  - converts with the pinned backend.

  Rules are included or excluded whole; their content is never edited.

### 4.3 Attack-sample split

Files are split by the SHA-256 of their content: even last hex digit → **development**,
odd → **report**. Selection uses only the development half. The report half is measured
once, after the shipped-rule manifest is frozen, and reported as exposed evidence.

### 4.4 Benign corpus (no personal data)

- Logs come only from **Windows virtual machines the team creates for this purpose**, using
  Microsoft's free evaluation images (their terms are checked and recorded at acquisition).
  Accounts are invented (`etis-user1`, `etis-admin`).
- No real person's PC, account or documents are used.
- A committed scenario script drives a typical home or small-office workload, including
  legitimate actions that resemble attacks:
  - software installs that create services and scheduled tasks;
  - Windows and Defender updates;
  - an administrator creating a user and adding it to Administrators once;
  - RDP from the LAN;
  - administrative PowerShell scripts;
  - a few mistyped passwords.
- At least **14 host-days** in total (for example 2 VMs × 7 days), with audit policy and
  script block logging enabled so that all §1.1 events can occur.
- The exported EVTX files stay local and ignored. Only a manifest of host-days, event
  counts and file hashes is committed.
- Known corpus actions are listed in the scenario log, so the benign alerts they trigger
  stay visible in reports. They are counted, not excused.

### 4.5 Gates

1. **Per-rule false-alarm limit:** at most 1 alert per 7 benign host-days (≤ 2 alerts over
   14 host-days).
2. **Per-rule evidence:**
   - If the development half contains a file whose manifest technique matches the rule's
     mapped technique, the rule must alert on at least one such file.
   - If no such file exists, the rule must pass its invented positive and negative unit
     tests. It then ships flagged `unvalidated_on_samples`, with confidence capped at
     `single_signal`.
3. **Shipped-set false-alarm limit:** all shipped rules together produce at most 1 medium-or-higher
   alert per benign host-day. If exceeded, remove rules in descending order of benign alert
   count until the limit holds. Ties remove Sigma before native, then lower level first.
4. **CPU limit:** parsing plus evaluation of 100,000 events takes ≤ 60 s (p95 over 5 runs)
   on the project PC.

### 4.6 Output

A shipped-rule manifest is committed before the report half is measured. It lists the
native rule ids with constants, and the Sigma rule ids, paths, authors and file SHA-256s.
Reported but never gating: per-technique detection on the report half, benign alerts per
rule and per scenario action, rules excluded and why, and channel coverage.

## 5. ATT&CK v20.0

### 5.1 Target techniques (all checked: present, neither revoked nor deprecated)

`T1110.001`, `T1110.003`, `T1136.001`, `T1098.007`, `T1059.001`, `T1027.010`, `T1105`,
`T1543.003`, `T1053.005`, `T1685.005`, `T1685.001`, `T1133`, `T1021.001`, `T1685`, plus
`T1078.003` Local Accounts, used only as a secondary tag when a successful logon follows H1/H2.

### 5.2 Revoked ids that Sigma rules still use

v20.0 revoked several ids that detection content commonly uses. The local catalogue's
`revoked-by` relationships give:

| Old id (revoked) | Replacement in v20.0 |
| --- | --- |
| `T1070.001` Clear Windows Event Logs | `T1685.005` Clear Windows Event Logs |
| `T1562.001` Disable or Modify Tools | `T1685` Disable or Modify Tools |
| `T1562.002` Disable Windows Event Logging | `T1685.001` Disable or Modify Windows Event Log |
| `T1562` Impair Defenses | `T1685` Disable or Modify Tools |
| `T1562.006` Indicator Blocking | `T1685` Disable or Modify Tools |

ETIS builds this remap from the local catalogue, not by hand, and applies it to Sigma tags.
Revoked or unknown ids are never emitted; `record_findings` still validates.

## 6. Findings

### 6.1 Unit and identity

Matches are grouped per (detection, host pseudonym, account pseudonym where relevant,
1-hour window) into **one Finding**. Engine `host.windows`, version
`host-v1+sigma:<release tag>+rules:<manifest sha256 prefix>`; observation kind
`evtx_batch`; source `{kind: import, ref: host_imports:<id>}`.

### 6.2 Severity

| Detection | Severity |
| --- | --- |
| H1 failed-logon flood | medium; **high** if a successful 4624 for the same account follows from the same source within 30 min |
| H2 password spraying | high |
| H3 new local account | medium; **high** if H4 follows for the same account within 1 h |
| H4 added to Administrators | high |
| H5 / Sigma | the rule's `level` (medium, high, critical) |
| H6 new service, H7 new task | low when native-only (installers create these routinely); the Sigma rule's level when a Sigma rule matches the same event |
| H8 log cleared or auditing disabled | high |
| H9 RDP from outside | medium; **high** if H1/H2 from the same source preceded it |
| H10 Defender disabled | high |

Severity is a fixed table, never derived from a score.

### 6.3 Confidence (categorical)

| Condition | Confidence |
| --- | --- |
| Two independent detections agree on the same host and window (for example H2 then H9, native H6 plus a Sigma rule) | corroborated |
| A single detection | single_signal |
| Rule shipped `unvalidated_on_samples` | at most single_signal |

`confirmed` is never used: ETIS cannot verify ground truth on the user's PC.

### 6.4 Indicators (hash only)

| Type | From | Role |
| --- | --- | --- |
| `ip` | Source address of 4624/4625/1149, Sysmon 3 destination, only for alerted events and only when not local (RFC 1918, loopback, link-local, `--local-net`) | `remote_endpoint` |
| `domain` | Sysmon 22 `QueryName`, Sysmon 3 `DestinationHostname`, hosts of URLs in alerted PowerShell script blocks | `resolved_name` / `download_host` |
| `url` | URLs in alerted PowerShell script blocks | `download_url` |
| `hash` | Sysmon 1 `Hashes` (SHA256, else SHA1, else MD5) of alerted process events | `executed_file` |

All are sent hash-only (`value=None`). URL and domain extraction reuses the existing URL
parser, which never fetches.

**Local usernames and computer names are never indicators.** They appear only as
`account_ref` and `host_ref`: HMAC-SHA-256 with a dedicated local key
(`ETIS_HOST_PSEUDONYM_KEY`, generated by `scripts/initialize.py` into ignored `.env`).
Well-known built-in principals (`S-1-5-18` SYSTEM, LOCAL SERVICE, NETWORK SERVICE) are
recorded by their well-known SID, because they identify no person.

### 6.5 Evidence details

Detection id; Sigma attribution block (§2.2); event counts per EventID and channel;
window start and end; `host_ref`, `account_ref`; logon type; source locality
(local/outside); coverage flags; the import's input file SHA-256; and up to 20
`EventRecordID`s, so the user can find the events in their own file. Never: usernames,
computer names, addresses, command lines, script text, file paths or service names.

### 6.6 Correlation with existing incidents

Findings go through the unchanged `record_findings`. Examples:

- A phishing SMS link domain → a Sysmon DNS query or a PowerShell download from the same
  registered domain → **same incident**.
- An outside RDP source address that also appears in a `network.flows` finding → same
  incident through the `ip` pivot.
- An executable hash → joins future malware-engine findings through the `hash` pivot.

Core v1 exclusions apply (shared hosting, official brand domains and hotlines, analyst
stoplist). Local pseudonyms never pivot. Low-severity findings (native H6/H7) never open
incidents.

### 6.7 Console, API and health

`GET /host/imports` and `GET /host/imports/{id}` show coverage, counts and findings, with a
"Host imports" section in Arabic and English. Sigma findings show author and source. There
is no upload endpoint. The engine registers only if the shipped-rule manifest and its
pinned Sigma package verify; health reports `rules_missing` or `sigma_backend_unavailable`
(native rules still run).

## 7. Privacy

| Stored in the ETIS database | Never stored, never leaves the PC |
| --- | --- |
| Import record: input file SHA-256, size, event counts per channel/EventID, time span, coverage, rule-manifest version | The EVTX files (read in place) and every event's content |
| Findings with hashed `ip`/`domain`/`url`/`hash` indicators | Usernames, computer names, SIDs of real users (only HMAC references) |
| `host_ref`/`account_ref` HMACs, EventRecordIDs | Command lines, PowerShell script text, file paths, service and task names |
| Rule ids and Sigma attribution | The in-memory SQLite table (destroyed after the import) |

- Nothing is sent to any service. There are no hash, IP or domain reputation lookups, and
  no observed address or URL is contacted.
- Logs record reason codes only.
- Import-derived findings expire after `ETIS_HOST_RETENTION_DAYS` (default 30), with the
  core v1 orphan-indicator clean-up and `findings_expired` events.
- Exported EVTX files contain personal data. The import command warns the user to keep them
  private and never asks for them to be shared.

## 8. Test plan

1. **Reader:** a tiny, team-made EVTX fixture recorded on a throwaway VM with invented
   names (for example via `eventcreate`) parses into normalised records. Corrupt and
   truncated files fail with reason codes. Limits are enforced.
2. **Normaliser:** invented event dictionaries for every §1.1 EventID give the expected
   flat fields; the in-memory table is gone after the import.
3. **Native detections:** table-driven positives and negatives for H1–H10 at their exact
   constants (19 vs 20 failures, 9 vs 10 accounts, local vs outside source, the
   Administrators SID vs another group), plus combinations and window edges.
4. **Sigma harness:** pinned conversion of a handful of invented Sigma-format test rules;
   `REGEXP`; excluded-rule accounting; the revoked-id remap produced from the local fixture
   catalogue; the attribution block present on every Sigma finding.
5. **Selection rule:** gates, split by content hash, tie order, shipped-set reduction,
   `unvalidated_on_samples` cap — table-driven, before any real measurement.
6. **Findings:** grouping, severity and confidence tables, indicator extraction (local
   addresses never emitted, hash precedence SHA256 > SHA1 > MD5), ATT&CK ids validated
   against the v20.0 fixture.
7. **Privacy:** marker strings placed in usernames, computer names, command lines, script
   text, paths and addresses never reach findings, indicators, events, import records or
   logs. HMACs are stable with one key and change with another.
8. **Correlation:** a host finding with a download host joins an existing phishing incident
   by registered domain; local pseudonyms never pivot; low severity opens no incident.
9. **No network access:** the import runs with sockets blocked.
10. **Regression:** the `/analyze` parity gate, the full suite, database initialization,
    frontend build and lint pass at every commit.

## 9. Implementation order (small commits)

Each commit runs pytest, database initialization, frontend build and lint. Downloads in
steps 5 and 6 need the owner's explicit approval first.

1. `feat: evtx reader and event normalisation` — pinned `evtx`, team-made fixture, limits (§8.1–8.2).
2. `feat: host pseudonyms and coverage report` — HMAC key in initialize, locality rules (§8.7).
3. `feat: native host detections H1-H10` — invented events (§8.3).
4. `feat: sigma evaluation harness on in-memory sqlite` — pinned pySigma + sqlite backend,
   Windows pipeline, `REGEXP`, revocation remap (§8.4).
5. `chore: SigmaHQ release fetch, lock and licence entry` — DRL entry, rules ignored.
6. `chore: EVTX-ATTACK-SAMPLES fetch, lock and licence entry` — GPL-3.0 entry, data ignored.
7. `docs: host technique manifest and frozen selection rule` — per-file labels and §4 frozen
   with SHA-256, before any measurement.
8. `chore: benign VM scenario and corpus manifest` — scenario script committed; logs local.
9. `feat: host rule evaluation and shipped-rule manifest` — gates, selection, report.
10. `feat: host.windows engine` — grouping, severity, confidence, indicators, attribution,
    registry and health.
11. `feat: migration for host imports and import command` — next free migration number.
12. `feat: retention for host import findings`.
13. `feat: host imports API and console section` — Arabic and English, Sigma author display.
14. `docs: host engine v1 implementation notes` — README, LOCAL-IMPLEMENTATION, api-v2,
    data-licences, engine-authors example.

## Sources checked for this design (18 November 2026)

- SigmaHQ rules repository: https://github.com/SigmaHQ/sigma
- Detection Rule License 1.1: https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md
- pySigma licence (LGPL-2.1): https://raw.githubusercontent.com/SigmaHQ/pySigma/main/LICENSE
- pySigma SQLite backend (features, limits; LGPL-3.0): https://github.com/SigmaHQ/pySigma-backend-sqlite
- `evtx` on PyPI (MIT, wheels, versions): https://pypi.org/project/evtx/
- EVTX-ATTACK-SAMPLES (GPL-3.0, organisation): https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- OTRF Security-Datasets (MIT licence file): https://github.com/OTRF/Security-Datasets and https://raw.githubusercontent.com/OTRF/Security-Datasets/master/LICENSE
- Security Datasets site (atomic/compound organisation): https://securitydatasets.com/introduction.html
- OTRF atomic dataset layout (secondary summary): https://fkie-cad.github.io/COMIDDS/content/datasets/otfr_atomic

ATT&CK ids and revocations were checked against the local, hash-verified
`data/external/attack/enterprise-attack-20.0.json`.
