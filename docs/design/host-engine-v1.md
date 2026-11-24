# Host engine v1 (`host.windows`) — design

Status: **design approved** (18 November 2026) with **amendment 1** (24 November 2026,
below), branch `feat/host-design`. No code, no dataset or rule download, no measurement
accompany this document.

### Amendment 1 (24 November 2026, approved by the owner, before any measurement)

1. **Benign corpus.** The team-built VM corpus is replaced by the **owner's own Windows PC
   event logs**, used with the owner's explicit consent (granted 24 November 2026),
   processed only locally and never committed. Only aggregate counts per rule and per
   host-day may be committed. At least 14 host-days are required if the logs reach back
   that far; otherwise the actual span is recorded. Reports say "one owner PC, one user's
   habits". Owner-PC alerts are reviewed by the owner and are not assumed benign. Team VMs
   are a later optional addition (§4.4).
2. **Three detections added:** H11 Office application starting a shell or script host,
   H12 shadow copy deletion, H13 run-as with another account's credentials from an
   unusual account (§2.1). Their ATT&CK ids were checked in the local v20.0 catalogue
   (§5.1).

Sections changed: §0, §1.1, §2.1, §4 (intro, 4.1, 4.4, 4.5), §5.1, §6.2–6.5, §8.3, §9.

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
| Honest claims | Evaluation uses public lab samples and one owner PC's logs as the benign corpus ("one owner PC, one user's habits"). Results are exposed development evidence, not accuracy on Egyptian PCs. |
| Owner's logs stay private | Read in place on the owner's PC; only aggregate counts per rule and per host-day are committed (§4.4). |

## 1. Input: Windows event logs exported by the user

### 1.1 Channels

| Channel | Required | Key events used |
| --- | --- | --- |
| `Security` | Yes | 4624 logon (LogonType, IpAddress), 4625 failed logon, 4740 lockout, 4720 account created, 4732/4728/4756 member added to a group, 4697 service installed, 4698 scheduled task created, 4719 audit policy changed, 1102 audit log cleared, 4648 logon with explicit credentials, 4688 process created (`NewProcessName`, `ParentProcessName`, `CommandLine`) |
| `System` | Yes | 7045 service installed, 7040 service start type changed, 7036 service state, 104 log cleared |
| `Microsoft-Windows-PowerShell/Operational` | Yes | 4104 script block, 4103 module/pipeline |
| `Microsoft-Windows-Windows Defender/Operational` | Recommended | 5001 real-time protection disabled, 5010/5012 scanning disabled, 5007 configuration changed |
| `Microsoft-Windows-TaskScheduler/Operational` | Optional | 106 task registered |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | Optional | 1149 RDP authentication (source address) |
| `Microsoft-Windows-Sysmon/Operational` | Optional | 1 process creation (with `Hashes`), 3 network connection, 13 registry value set, 22 DNS query |

Many events are absent under Windows' default audit policy. For example, 4698 and 4697
need object-access and system auditing, full 4104 logging needs script block logging,
4688 needs process-creation auditing, and its `CommandLine` needs the "include command
line in process creation events" policy. H11 and H12 run on 4688 or Sysmon 1.
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
| H11 | Office application starts a shell or script host | ETIS-native + Sigma | 4688 or Sysmon 1 whose parent image file name is `winword.exe`, `excel.exe`, `powerpnt.exe` or `outlook.exe` and whose image file name is `powershell.exe`, `pwsh.exe`, `cmd.exe`, `wscript.exe` or `mshta.exe` (file names compared case-insensitively, directories ignored) | `T1204.002` Malicious File; secondary by child: `T1059.001` PowerShell (`powershell.exe`, `pwsh.exe`), `T1059.003` Windows Command Shell (`cmd.exe`), `T1059.005` Visual Basic (`wscript.exe`), `T1218.005` Mshta (`mshta.exe`) |
| H12 | Shadow copy deletion (ransomware warning sign) | ETIS-native + Sigma | 4688 or Sysmon 1 with image file name and lower-cased, whitespace-collapsed command line: `vssadmin.exe` containing `delete shadows`; `wmic.exe` containing `shadowcopy` and `delete`; `wbadmin.exe` containing `delete catalog`, `delete systemstatebackup` or `delete backup`. Without a command line the detection is "not visible". | `T1490` Inhibit System Recovery |
| H13 | Run-as with another account's credentials from an unusual account | ETIS-native | 4648 whose `TargetServerName` is local (`localhost`, `127.0.0.1`, `::1` or the event's own computer name) and whose subject account differs from the target account (name and domain, case-insensitive); subject is not a machine account (name ending `$`), not `S-1-5-18`/`-19`/`-20` and not `-`. **Unusual:** the (subject, target) pair did not occur in a qualifying 4648 during the first 24 h of the import's covered span (the baseline). Imports covering less than 48 h have no baseline: every qualifying pair is treated as unusual and the finding records `baseline: none`. | `T1134.002` Create Process with Token; secondary `T1078` Valid Accounts |

Combinations raise severity or confidence but never create a separate kind (§6.2–6.3):
for example H3 then H4 for the same account, H1/H2 then a successful 4624 or H9 from
the same source, or H11 followed by H5 or H12 on the same host within the window.

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
one owner PC with one user's habits, and neither represents Egyptian users' PCs.

### 4.1 Decision: rules only, no ML component in v1

ML is **not a candidate** in v1:

- Public attack samples have no per-event labels; files mix attack and background events.
- No sizeable, labelled benign host-event corpus from the target population exists. One
  owner PC would teach a model one user's habits.
- Rules are explainable, carry ATT&CK tags and Sigma author attribution, and each can be
  tested on invented events.

ML is reconsidered only if a labelled benign and attack corpus becomes available, under a
new frozen rule.

### 4.2 Candidate pool (fixed)

- **Native:** H1–H4, H6–H13 native parts, with the constants in §2.1. Never tuned.
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

### 4.4 Benign corpus: the owner's own PC (amendment 1)

- Logs come from the **owner's own Windows PC**, exported by the owner (§1.2) and used with
  the owner's explicit consent (granted 24 November 2026). They are processed only locally
  on that PC and are never committed, uploaded or shared. No other person's PC is used.
- **Host-day:** a UTC calendar day lying wholly inside the covered span of every
  *required* channel export (`Security`, `System`, `PowerShell/Operational`). Partial days
  at either end are excluded. Logs that roll over early therefore give fewer host-days.
- At least **14 host-days** are required if the logs reach back that far. If they do not,
  the actual number of host-days and the span are recorded and used; nothing is padded or
  extrapolated. The owner's audit policy is used as found; detections it hides are
  reported as "not visible", not as clean days.
- **Committed:** only aggregate counts — alerts per rule; alerts and events per host-day
  (host-days numbered 1…N, not dated); events per channel and EventID; host-day count;
  per-rule counts by review label (below). **Never committed:** the EVTX files, their
  hashes or names, any event field, usernames, computer names, paths, command lines,
  timestamps or record numbers. Per-alert review material stays under ignored
  `evaluation/local-results/host-v1/`.
- **Owner review, not assumed benign.** Every owner-PC alert is reviewed by the owner and
  labelled `benign_explained`, `unexplained` or `suspected_malicious` before gates are
  computed. `benign_explained` and `unexplained` alerts both count as false alarms for
  gates 1 and 3 (a rule gets no credit for an unverified detection). A
  `suspected_malicious` alert is excluded from false-alarm counts, reported separately,
  and the owner is told to check the PC; if any exist, the report states that the benign
  corpus may itself be contaminated.
- Reports always say **"one owner PC, one user's habits"**.
- **Team VMs are a later optional addition.** If added, they are a separately frozen
  amendment with their own host-day counts, reported alongside, never merged silently.

### 4.5 Gates

1. **Per-rule false-alarm limit:** at most 1 alert per 7 benign host-days, i.e. at most
   ⌊N / 7⌋ alerts over N host-days (≤ 2 over 14; 0 if N < 7).
2. **Per-rule evidence:**
   - If the development half contains a file whose manifest technique matches the rule's
     mapped technique, the rule must alert on at least one such file.
   - If no such file exists, the rule must pass its invented positive and negative unit
     tests. It then ships flagged `unvalidated_on_samples`, with confidence capped at
     `single_signal`.
3. **Shipped-set false-alarm limit:** all shipped rules together produce at most 1 medium-or-higher
   alert per benign host-day (at most N over N host-days). If exceeded, remove rules in descending order of benign alert
   count until the limit holds. Ties remove Sigma before native, then lower level first.
4. **CPU limit:** parsing plus evaluation of 100,000 events takes ≤ 60 s (p95 over 5 runs)
   on the project PC.

### 4.6 Output

A shipped-rule manifest is committed before the report half is measured. It lists the
native rule ids with constants, and the Sigma rule ids, paths, authors and file SHA-256s.
Reported but never gating: per-technique detection on the report half, benign alerts per
rule, per host-day and per review label (§4.4), rules excluded and why, and channel coverage.

## 5. ATT&CK v20.0

### 5.1 Target techniques (all checked: present, neither revoked nor deprecated)

`T1110.001`, `T1110.003`, `T1136.001`, `T1098.007`, `T1059.001`, `T1027.010`, `T1105`,
`T1543.003`, `T1053.005`, `T1685.005`, `T1685.001`, `T1133`, `T1021.001`, `T1685`, plus
`T1078.003` Local Accounts, used only as a secondary tag when a successful logon follows H1/H2.

Added by amendment 1 (checked 24 November 2026 in the local v20.0 catalogue, SHA-256
`2339a3c3…b4278`; each present, not revoked, not deprecated, platform Windows):

| Id | Name | Tactics (v20.0) | Used by |
| --- | --- | --- | --- |
| `T1204.002` | Malicious File | execution | H11 |
| `T1059.003` | Windows Command Shell | execution | H11 (secondary) |
| `T1059.005` | Visual Basic | execution | H11 (secondary) |
| `T1218.005` | Mshta | stealth | H11 (secondary) |
| `T1490` | Inhibit System Recovery | impact | H12 |
| `T1134.002` | Create Process with Token | privilege-escalation, stealth | H13 (v20.0 text names `runas`) |
| `T1078` | Valid Accounts | initial-access, persistence, privilege-escalation, stealth | H13 (secondary) |

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
| H11 Office application starts a shell or script host | high |
| H12 shadow copy deletion | high |
| H13 run-as from an unusual account | medium; **high** if H3 or H4 involved the same target account within 1 h |

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
| `hash` | Sysmon 1 `Hashes` (SHA256, else SHA1, else MD5) of alerted process events, including H11 and H12 | `executed_file` |

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
(local/outside); for H11 the parent and child image *file names* only (fixed list values,
e.g. `winword.exe` → `powershell.exe`); for H12 the tool file name; for H13 `baseline:
24h|none`; coverage flags; the import's input file SHA-256; and up to 20
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

1. **Reader:** a tiny EVTX fixture with invented names parses into normalised records.
   Corrupt and truncated files fail with reason codes. Limits are enforced.
   *Implementation note (24 November 2026):* no team VM exists, so instead of recording
   the fixture on one, a test-only writer (`backend/tests/evtx_writer.py`) builds valid
   EVTX files (headers, chunks, template-free binary XML, CRC32s) from invented events at
   test time; the pinned parser reads them with checksum validation on. No real machine's
   log is recorded or committed. Template-based records, as Windows writes them, are first
   exercised by the attack samples.
2. **Normaliser:** invented event dictionaries for every §1.1 EventID give the expected
   flat fields; the in-memory table is gone after the import.
3. **Native detections:** table-driven positives and negatives for H1–H13 at their exact
   constants (19 vs 20 failures, 9 vs 10 accounts, local vs outside source, the
   Administrators SID vs another group; H11 each listed parent × child vs `explorer.exe`
   parent and `notepad.exe` child; H12 each tool's delete form vs `vssadmin list shadows`
   and a missing command line; H13 same vs different account, machine and well-known
   subjects, remote target, pair inside vs after the 24 h baseline, and spans of 47 h vs
   48 h), plus combinations and window edges.
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

1. `feat: evtx reader and event normalisation` — pinned `evtx`, generated invented fixture, limits (§8.1–8.2).
2. `feat: host pseudonyms and coverage report` — HMAC key in initialize, locality rules (§8.7).
3. `feat: native host detections H1-H13` — invented events (§8.3).
4. `feat: sigma evaluation harness on in-memory sqlite` — pinned pySigma + sqlite backend,
   Windows pipeline, `REGEXP`, revocation remap (§8.4).
5. `chore: SigmaHQ release fetch, lock and licence entry` — DRL entry, rules ignored.
6. `chore: EVTX-ATTACK-SAMPLES fetch, lock and licence entry` — GPL-3.0 entry, data ignored.
7. `docs: host technique manifest and frozen selection rule` — per-file labels and §4 frozen
   with SHA-256, before any measurement.
8. `chore: owner-PC benign corpus aggregates` — the owner exports their own logs (§1.2);
   only the aggregate counts of §4.4 are committed; logs and review material stay local.
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
