# Network-lite engine v1 for Windows (`network.windows`) — design

Status: **design only** (26 November 2026), branch `feat/network-windows-design`, with the
review answers of 26 November 2026 (§10), and the step 1 verification of 26 November 2026
(§11, Sources). Apart from the step 1 readers, no code, download, measurement or system change
accompanies this document. A fact is marked **verified** only when it was read on the cited
page or local provider manifest (Sources); every other fact about Windows, Sysmon, blocklists and sample data
is marked **to verify**, with the page to read, and is listed again in §11. No number in this
document comes from a measurement.

`network.windows` gives ETIS network visibility on a single Windows PC **without Linux,
WSL or Zeek**. It reads logs that the owner has already turned on and exported from their
own PC (DNS Client log, Windows Firewall log, optional Sysmon events and optional local
connection snapshots), applies a fixed list of explainable rules and offline lists, and
emits `finding-v1` Findings through the core v1 path ([core v1](core-v1.md) §1, §8;
[engine authors](../engine-authors.md)). It follows the structure of the
[host engine design](host-engine-v1.md) and reuses decisions of the
[network engine design](network-engine-v1.md) (`network.flows`) where they apply. It never
touches `/analyze`, the phishing thresholds or any frozen model.

## 0. Constraints

| Constraint | How this design keeps it |
| --- | --- |
| Windows only, free and local | Python on the owner's Windows PC. No Linux, WSL, Zeek, packet capture driver, SIEM, cloud or paid service. |
| Nothing leaves the PC | Logs are read in place. No DNS resolution, reverse DNS, WHOIS, geolocation, reputation or any other online lookup; no observed address or domain is contacted (as `network.flows` §6). Blocklists are local files refreshed only by an explicit owner command that sends nothing about the PC (§2.2). |
| ETIS never changes the system | ETIS never turns a log on, changes a firewall setting, installs Sysmon or creates a scheduled task. Turning a source on is a deliberate owner action with administrator rights (§1). |
| Indicators are inert | Domains and IPs are strings: hashed, never fetched. The phishing URL model scores a domain string only (§2.1 N4). |
| No full browsing history | DNS and connection records live only in memory during an import. Only alerted destinations become hash-only indicators; everything else is counted (§7). |
| Phishing path unchanged | Separate engine and rules. The URL model is used with its frozen artifact and threshold, read-only. The `/analyze` parity gate keeps running. |
| Data licences | Blocklists and samples stay under ignored `data/external/`; `docs/data-licences.md` entries before acquisition (§3). |
| Honest claims | Benign evidence is one owner PC ("one owner PC, one user's habits"). Attack evidence is invented or public samples. Results are exposed development evidence except the one sealed test (§4.9). |

### 0.1 Coexistence with `network.flows` (Zeek, paused)

| | `network.flows` | `network.windows` |
| --- | --- | --- |
| Input | Zeek `conn.log`/`dns.log` from a sensor or WSL | Windows logs exported from one PC |
| Status | Paused at step 3 until WSL is installed (network-engine-v1 §8) | This design |
| Method | Trained flow model (UNSW-NB15) | Fixed rules and offline lists; no trained model |
| Engine name / kinds | `network.flows`; `network_*` kinds | `network.windows`; the kinds of §6.2 (no overlap) |
| Indicator roles | `remote_endpoint` (ip), `resolved_name` (domain) | the same roles, so the same remote IP or domain joins one incident through core correlation |
| Local identity | `local_host_ref` = HMAC of a local IP (`ETIS_NETWORK_PSEUDONYM_KEY`) | `device_ref` = HMAC of the computer name with the host key (§6.5), equal to the host engine's `host_ref` |
| Storage | `network_imports` table | `network_windows_imports` table (§9 step 10) |
| Retention | `ETIS_NETWORK_RETENTION_DAYS` | the same variable (one network retention setting) |

Both can be registered at once. They never deduplicate each other: a destination seen by
both gives two Findings that meet in one incident through the shared indicator. If
`network.flows` resumes, running the §2 rules on Zeek `dns.log`/`conn.log` through an
adapter is a possible later amendment, not part of v1.

## 1. Input: logs the owner turns on and exports

Every source is **read-only and local**. ETIS documents how to turn each source on; it never
does it. Every Windows fact in this section is **to verify** (§11, items W1–W12) on the
Microsoft Learn page named in the table, or, where no page is found, from the event
provider's own manifest on the owner's PC (`wevtutil gp <provider> /ge /gm:true`, a local
read-only command).

### 1.1 Sources

| Source | Event ids / records used | Fields used | Default state (to verify) | How the owner turns it on (to verify) | Page to read |
| --- | --- | --- | --- | --- | --- |
| **DNS Client log** `Microsoft-Windows-DNS-Client/Operational` | 3006 query started; 3008 query completed; 3020 query response (**verified**, provider manifest, W1) | 3006: `QueryName`, `QueryType`, `QueryOptions`; 3008: `QueryName`, `QueryType`, `QueryOptions`, `QueryStatus`, `QueryResults`; 3020: `QueryName`, `QueryType`, `Status`, `QueryResults`, and `ClientPID` from event version 1 (**verified**, provider manifest, W2); `TimeCreated`, `Computer` from the event header. The header process id is not used. | Off | Event Viewer → Applications and Services Logs → Microsoft → Windows → DNS Client Events → Operational → *Enable Log*; or, as administrator, `wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true`. Also raise its maximum size (`/ms:`), since the default is small and rolls over quickly. | `wevtutil` command reference (learn.microsoft.com, windows-commands/wevtutil); event ids and fields from the provider manifest (W1–W3) |
| **Windows Firewall log** `pfirewall.log` | Text lines, one per allowed or dropped connection | `date`, `time`, `action` (ALLOW/DROP), `protocol`, `src-ip`, `dst-ip`, `src-port`, `dst-port`, `size`, `path` (SEND/RECEIVE), `pid` if present on the Windows build | Off (no dropped or allowed logging); default path `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`; default maximum 4,096 KB | Windows Defender Firewall with Advanced Security → Properties → each profile → Logging → *Log dropped packets* and *Log successful connections* = Yes, size raised; or `Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes <n>`; or `netsh advfirewall set allprofiles logging allowedconnections enable` / `droppedconnections enable` | "Configure Windows Firewall logging" (learn.microsoft.com, windows/security/.../windows-firewall/configure-logging); `Set-NetFirewallProfile` (learn.microsoft.com/powershell/module/netsecurity) (W4–W7) |
| **Sysmon** `Microsoft-Windows-Sysmon/Operational` (optional, only if the owner already installed Sysmon) | 3 network connection; 22 DNS query; 1 process creation (only to join a connection to the process's file hash, §6.4) | Event 3: `Image`, `ProcessGuid`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationHostname`, `DestinationPort`. Event 22: `QueryName`, `QueryStatus`, `QueryResults`, `Image`, `ProcessGuid`. Event 1: `ProcessGuid`, `Hashes` | Sysmon is not part of Windows. Event 3 is logged only when the configuration enables network connection logging; event 22 depends on the configuration and Windows version | The owner installs Sysmon and chooses a configuration; ETIS never ships or installs one | Sysmon page (learn.microsoft.com/sysinternals/downloads/sysmon) (W8–W10) |
| **Connection snapshots** (optional) | One row per TCP connection or UDP endpoint at the snapshot time | Local and remote address and port, state, owning process id; process image *file name* resolved at snapshot time only for the evidence category (§6.5) | Not a Windows log: produced by `data/scripts/snapshot_connections.py`, which the owner runs | The owner runs the command by hand, or creates their own scheduled task. ETIS never creates the task. Reading other users' process owners may need administrator rights (to verify) | `GetExtendedTcpTable` / `GetExtendedUdpTable` (learn.microsoft.com, win32/api/iphlpapi), called through `ctypes`, standard library only; `Get-NetTCPConnection` as the documented PowerShell equivalent (W11–W12) |

The snapshot command only reads the connection tables and writes a local JSON-lines file
under ignored `var/network-snapshots/` (its rows hold addresses; it is an input file, like an
exported log, and the import treats it the same way). It never kills, blocks or contacts
anything. Snapshots miss short connections; they are a supplement when firewall logging is
off, not a substitute.

### 1.2 Coverage report

As in host-engine-v1 §1.1, every import produces a coverage report: sources present, time
span per source, and the detections that could not run. A detection that could not run is
shown as **not visible**, never as "nothing found". Examples: no DNS Client log → N3, N4,
N5, N8 and the DNS parts of N9 are not visible; no firewall log, Sysmon 3 or snapshot → N1
connection checks, N6, N7 are not visible; DNS without `QueryType` → the TXT part of N8 is
not visible.

### 1.3 How the owner supplies it

```
wevtutil epl Microsoft-Windows-DNS-Client/Operational C:\exports\dns.evtx     (owner, admin prompt)
copy %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log C:\exports\         (owner, admin prompt)
python data/scripts/import_network_windows.py --dns-evtx C:\exports\dns.evtx
        [--firewall-log C:\exports\pfirewall.log] [--sysmon-evtx C:\exports\sysmon.evtx]
        [--snapshots var\network-snapshots\*.jsonl] [--local-net 192.168.1.0/24]
```

Files are read in place and never copied. EVTX files are parsed with the already pinned
`evtx` reader of the host engine (`backend/app/engines/host/reader.py`), so no new parser
library is needed for EVTX. The firewall log is a W3C-style text file with a `#Fields:`
header (to verify, W5) and is parsed by a small standard-library reader that refuses unknown
headers. No browser upload. Limits: 2,000,000 DNS events, 2,000,000 firewall lines,
1,000,000 Sysmon events and 1 GB per import, checked before parsing where possible and
fail-closed otherwise.

### 1.4 Normalised records (in memory only)

- **DNS record:** time (UTC), device name, process id or image file name if present,
  query name (lower-cased, trailing dot removed, IDNA A-label form through the existing
  `app.core.url_utils` helpers), query type, status, answer IPs.
- **Connection record:** time (UTC), device name, direction (outbound when initiated locally
  or `path = SEND`), action (allowed, dropped), protocol, remote IP and port, local port,
  process id or image file name if present, source (`firewall`, `sysmon3`, `snapshot`).
- Locality: RFC 1918, loopback, link-local, multicast, broadcast, CGNAT `100.64.0.0/10`,
  IPv6 ULA and link-local, and `--local-net` are local (as host-engine-v1 §6.4 and
  network-engine-v1 §3.2). Local destinations are never evaluated by N1, N2, N6, N7, N9 and
  are never indicators.
- **Registered domain:** from the existing offline public-suffix handling in
  `app.core.url_utils.registered_domain` (to verify that it uses no network, W13).

All records are discarded when the import ends.

## 2. Detections

### 2.1 Fixed list

Constants are fixed here and never tuned; a change is a dated pre-result amendment (§4.10).
"Popular" means the registered domain is in the top 100,000 ranks of the existing local
Tranco snapshot `tranco_final_approved.csv` (no new list is fetched; its date and licence
are to verify, §11 item L5). The popular list is only an exclusion; it never marks anything
safe in a Finding.

| Id | Detection | Reason code(s) | Logic (fixed constants) | Sources |
| --- | --- | --- | --- | --- |
| N1 | Connection to, or DNS answer containing, an IP on a local offline **C2 blocklist** | `blocklist_ip_connection`, `blocklist_ip_dropped`, `blocklist_ip_dns_answer` | Exact match of a non-local remote IP against a loaded list (§2.2). An allowed outbound connection, a dropped one and an answer-only match are separate reason codes. | firewall, Sysmon 3, snapshot, DNS answers |
| N2 | DNS query or connection hostname on a local offline **malicious-host list** | `blocklist_host_query` | Exact match of the query name or its registered domain against a loaded host list (§2.2), with the list's own matching unit (full host or registered domain). **Inactive in v1:** no v1 list provides hosts (§10 decision 1); defined here so a later amendment can activate it without changing the other rules. | DNS, Sysmon 3 `DestinationHostname` |
| N3 | DNS query of a domain already in ETIS's **indicator store** | `indicator_store_domain_match` | The query's registered-domain hash equals the `registered_domain_hash` (or `value_hash`) of an active `domain` or `url` indicator from a phishing Finding or a feed (core v1 §2), after core exclusions (shared hosting, official brand domains, analyst stoplist) | DNS, Sysmon 22 |
| N4 | **Phishing URL model** on the queried domain | `url_model_domain_high` | The existing frozen URL candidate `ee0ba9f0077c1fd140aa` scores the inert string `https://<query name>/` with its `host_path` input and its frozen threshold `0.9870690448552604`; at or above → reason. Out of its training distribution (a bare host), so it is **corroboration only** (§6.3). Nothing is fetched, the model is not retrained, the threshold is not changed. | DNS |
| N5 | **DGA-like** domain | `dga_like_domain`, `dga_nxdomain_burst` | On the registered-domain label (left of the public suffix), not popular: length ≥ 10 **and** Shannon entropy ≥ 3.5 bits/character **and** (longest consonant run ≥ 5 **or** digit share ≥ 0.30). Burst: ≥ 10 distinct DGA-like registered domains answered "name does not exist" for one device within 10 minutes. | DNS |
| N6 | **Periodic beaconing** to one destination | `periodic_beaconing` | For one (device, destination) pair, destination = remote IP and port, or registered domain for DNS-only evidence, not local, not popular: ≥ 10 events spanning ≥ 30 minutes, median gap between 10 s and 3,600 s, and gap dispersion MAD / median ≤ 0.10. | firewall, Sysmon 3, snapshot (connections); DNS as fallback |
| N7 | **Unusual remote port** | `unusual_remote_port` | Allowed outbound TCP or UDP to a non-local IP whose destination port is not in the fixed set {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478–3481, 5223, 5228, 8080, 8443}, and whose (device, port) pair did not occur during the import's first 24 h (baseline as host H13; imports shorter than 48 h have `baseline: none`). | firewall, Sysmon 3, snapshot |
| N8 | **DNS tunnelling signs** | `dns_long_labels`, `dns_high_entropy_labels`, `dns_txt_burst`, `dns_very_long_name` | Per (device, registered domain), not popular, 10-minute window: ≥ 50 queries with distinct leftmost labels **and** (median leftmost-label length ≥ 25 **or** mean leftmost-label entropy ≥ 3.8); **or** ≥ 20 TXT (`QueryType` 16) queries; **or** any query name ≥ 120 characters. Each satisfied sign is its own reason code. | DNS (TXT needs `QueryType`) |
| N9 | **First-seen rare destination** | `rare_first_seen_destination` | Registered domain (or remote IP without a name) not in the top 1,000,000 of the local Tranco snapshot, first seen after the import's 24 h baseline (imports shorter than 48 h: `baseline: none`, nothing emitted). | DNS, connections |

Combinations raise severity or confidence (§6.2, §6.3) but never create another kind. No
packet capture, payload inspection, certificate check or online lookup is used by any rule.

### 2.2 Offline lists (layer of exact matches)

| List | Content used | Licence / terms | Status |
| --- | --- | --- | --- |
| abuse.ch **Feodo Tracker** IP blocklist | Botnet C2 IPs (N1) | **Verified (reviewer, 25 November 2026, abuse.ch terms of use §3.4):** "Feodo Tracker, SSL Blacklist, and YARAify are free to use without limitations according to Creative Commons principles (CC0)". List formats and update cadence **to verify (§11 L1)**. | **v1** (§10 decision 1) |
| abuse.ch **SSL Blacklist** (SSLBL) IP list | Botnet C2 IPs associated with malicious TLS certificates (N1). Certificate and JA3 lists are unusable: no source here sees TLS. | **Verified (same reading, terms §3.4):** CC0 as for Feodo Tracker. Whether the IP list is still published, and its format, **to verify (§11 L2)**; if it is no longer published, v1 uses Feodo Tracker alone. | **Not used** (note of 27 November 2026 below: deprecated on 2025-01-03) |
| abuse.ch **URLhaus** host list | Malware distribution hosts (N2) | **Verified in malware-engine-v1 §3.4 for abuse.ch generally:** free access is for not-for-profit use (terms §3.1–3.2); §7.3 forbids using the data to train or improve AI models without written consent. URLhaus-specific formats **to verify (§11 L3)** only if a later amendment proposes it. | **Not in v1** (§10 decision 1); later amendment only |
| ThreatFox, other feeds | — | **To verify (§11 L4)** before any proposal | Not in v1 |
| Existing ETIS indicator store | Phishing link domains and feed indicators (N3) | Existing core v1 data | Used as is |

Each list is pinned in `data/network-blocklists-lock.json` (source, URL, fetch time, file
size, SHA-256, row count, licence statement) and stored under ignored
`data/external/network-blocklists/`. Refresh is a separate owner command
(`data/scripts/fetch_network_blocklists.py`) that downloads the published lists only and
sends nothing about the PC; the import itself never downloads. A list older than 7 days is
still used and reported as `blocklists_stale` in health (§6.8). Lists are never used to
train, tune or evaluate a model. CC0 needs no attribution, but ETIS keeps it anyway: every
N1/N2 Finding carries the list name, version
(fetch time and SHA-256 prefix), licence and a link to the list's public page (attribution).

**Note (27 November 2026, owner decisions of that day, step 5).** The abuse.ch terms were re-read
before the fetch (page "Last Updated: 21st October 2026"); §3.4 still gives CC0 for Feodo Tracker
and SSL Blacklist (`docs/data-licences.md`).

- **SSL Blacklist is not used.** Its IP list file (`sslipblacklist.txt`) says in its own header
  "This list has been deprecated on 2025-01-03" (last updated 2025-01-02, 0 IP rows), although
  the list page shows no notice. As foreseen above, **v1 uses Feodo Tracker alone**: the
  recommended plain-text list `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`.
- **Limitation: N1 has very low practical coverage.** At fetch time Feodo Tracker held **1
  entry**, and its own header said "Last updated: 2026-03-04 14:28:39 UTC" (the list page also
  said "Our Feodo Tracker datasets are currently empty."). This is a stated limitation, **not a
  tuning target**: no list, rule or constant is added or changed because of it.
- **Source age.** The lock records the list's own "Last updated" header as `list_last_updated`.
  Health reports two ages: our fetch age (`blocklists_stale` after 7 days, as before) and the
  source's own age (`blocklist_source_stale` when the newest source header is older than 30
  days). `blocklist_source_stale` is informational only; it changes no detection rule (§6.8).

## 3. Evaluation data

### 3.1 Benign: the owner's own PC

As host-engine-v1 §4.4 (amendment 1): the owner's own Windows PC, with explicit consent,
processed only locally, aggregates only committed. Because the DNS Client log and firewall
logging are off by default, the benign corpus is **collected forward**: the owner turns the
sources on (§1.1), waits, then exports. The span actually covered is recorded.

### 3.2 Attack evidence (exposed, public or invented)

| Source | Use | Licence | Status |
| --- | --- | --- | --- |
| Invented logs generated at test time (DNS EVTX through the host engine's test-only EVTX writer, firewall text, Sysmon 3/22) | Positive and negative tests at every constant of N1–N9 | ETIS's own | Always |
| EVTX-ATTACK-SAMPLES (already pinned for the host engine) | Files that contain Sysmon 3 or 22 events (N1–N9 where applicable) | GPL-3.0 (already recorded in `docs/data-licences.md`) | **Used through path labels (step 6, 27 November 2026):** no sample carries a §5 gate technique; see §11 S1 |
| A public labelled DGA domain list (candidate: UMUDGA, on Mendeley Data, not Zenodo) | Domain strings only, as inert input to N5 | MIT on the dataset page (§11 S2) | **Not used: contains executables** (owner decision, 27 November 2026) |
| A public DNS-tunnelling sample in Windows log form | N8 | **To verify (§11 S3)**; public tunnelling samples are usually PCAP, which v1 does not read | Probably none; N8 then ships `unvalidated_on_samples` |
| Blocklist hits | N1/N2 exact matching is proven by unit tests with invented lists; no live malicious traffic is ever generated or replayed | — | Unit tests only |

Nothing is downloaded by this design. Each public source needs a `docs/data-licences.md`
entry and the owner's approval before acquisition, and stays under ignored `data/external/`.
Public samples are split by content SHA-256 (even last hex digit → development, odd →
report), as host-engine-v1 §4.3.

## 4. Frozen evaluation and selection rule

This section is the rule. Before any rule is run on any sample or on the owner's logs, it is
copied unchanged into `evaluation/reports/<date>-network-windows-v1/selection_rule.md` with
its SHA-256 recorded in `FREEZE.json`. This is an **exposed development protocol**: the
benign corpus is one owner PC with one user's habits, and the attack evidence is invented or
public. Only §4.9 is a sealed test.

### 4.1 Decision: rules and lists only, no trained model

No model is trained for v1. No labelled benign and attack corpus of Windows network logs
from the target population exists, and one PC would teach a model one user's habits. N4
uses the existing frozen phishing URL model read-only and only as corroboration.

### 4.2 Candidate pool (fixed)

- **Rules:** N1 and N3–N9 with the §2.1 constants. N2 is inactive in v1 (no host list).
- **Lists:** Feodo Tracker and SSL Blacklist (IP list, if still published), each a separate
  candidate; the exact fetch (lock SHA-256) is named in the frozen copy. URLhaus is not a v1
  candidate (§10 decision 1).

### 4.3 Units

- **Device-day:** a UTC calendar day lying wholly inside the covered span of every source
  present in the owner's import. Partial days are excluded.
- **Alert:** one grouped Finding as §6.1 defines it.
- **Imports:** the owner's files are one import; each public sample file is its own import
  (N7 and N9 therefore run with `baseline: none` on samples and emit nothing for N9).

### 4.4 Benign corpus (owner PC)

At least **14 device-days** after the sources are turned on, if the owner can wait that long;
otherwise the actual number N and span are recorded and used, never padded. Committed: alerts
per rule and per list, alerts and events per device-day (numbered 1…N, not dated), events per
source and event id, coverage, per-rule counts by review label. **Never committed:** the log
files, their names or hashes, any domain, IP, port per event, process name, user or computer
name, timestamp or record number. Review material stays under ignored
`evaluation/local-results/network-windows-v1/`.

### 4.5 Owner review (as host amendment 3)

Per rule or list, the owner sees locally a summary (alerts, device-days with alerts, the most
frequent destinations and processes) and up to 10 examples (all if ≤ 10, otherwise 10 evenly
spaced in time order, first and last included), and gives one label — `benign_explained`,
`unexplained` or `suspected_malicious` — with an optional split by alert number.
`benign_explained` and `unexplained` count as false alarms. `suspected_malicious` is
reported separately, the owner is told to check the PC with their installed antivirus, and
the report states the corpus may be contaminated. A blocklist hit can be labelled
`suspected_malicious` only if the owner's installed security product also flags the
destination or the process in a local check with cloud lookups and sample submission off;
otherwise it counts as `unexplained` (as malware-engine-v1 §4.6).

### 4.6 Gates (all must pass for the item to ship)

1. **Per-rule and per-list false-alarm limit:** at most ⌊N / 7⌋ alerts over N device-days
   (0 if N < 7). A failing rule or list is not shipped; the rest stay.
2. **Per-rule evidence:** if the development half of a public sample source contains a file
   expected to trigger the rule (expected-detection manifest frozen with this rule), the rule
   must alert on at least one such file. If no such file exists, the rule must pass its
   invented positive and negative tests; it then ships `unvalidated_on_samples` with
   confidence capped at `single_signal`.
3. **Shipped-set limit:** all shipped rules and lists together give at most N medium-or-higher
   alerts over N device-days (base severity, §6.2, without combination escalation). If
   exceeded, remove items in descending order of benign alert count; ties remove behavioural
   rules (N5–N9) before list rules (N1–N3), and N4 first of all.
4. **CPU limit:** parsing and evaluating 1,000,000 DNS events plus 1,000,000 firewall lines
   takes ≤ 120 s (p95 over 5 runs, after one warm-up) on the project PC. If it fails, nothing
   ships and a dated amendment is required before re-measuring.
5. **N4 specific:** N4 ships only if gate 1 holds for it; its threshold is never changed.

### 4.7 Output

A shipped-item manifest (rule ids with constants, list names with lock SHA-256s and
licences) is committed before the report half and before §4.9.

### 4.8 Reported, never gating

Detections on the report half; benign alerts per rule, per device-day and per review label;
the distribution of alerts per device-day; coverage; items removed and why; the N4 score
distribution on the owner's DNS names (counts in fixed bins only); the share of DNS queries
excluded as popular; time per source.

### 4.9 Sealed test

A one-shot sealed test of the frozen shipped manifest: (a) the report half of every public
sample source, and (b) a **forward** owner-PC window of 14 device-days that starts after the
manifest is frozen. It requires a target entry in `evaluation/targets.json` style, supervisor
approval and the owner's explicit instruction. It is run once and reported whatever the
result. It is not part of the implementation plan (§9).

### 4.10 Amendments

Any change after freezing is a dated pre-result amendment, approved by the owner, citing the
previous `selection_rule.md` SHA-256, stating that no result it could be tuned to has been
seen, and recorded in `FREEZE.json` (as host amendment 3). After the sealed test, no amendment
can affect its reported result.

### 4.11 Pre-measurement clarifications (27 November 2026)

Written before any rule was run on any sample or on the owner's logs, and before this section
was frozen, to remove choices that would otherwise be made after seeing results (as
host-engine-v1 §4.7). They take precedence over §4.1–4.10 where those are silent or ambiguous.

1. **Lists (§4.2).** The SSL Blacklist IP list is not a candidate: its file header says it was
   deprecated on 2025-01-03 (§2.2 note of 27 November 2026). The only list candidate is
   **Feodo Tracker**, the exact fetch pinned by `data/network-blocklists-lock.json` with
   raw-byte SHA-256 `692d3197a7aadbeae5a7803dbc7578395d1d041244ee1b77fb6765a535260b6c` (1 IP
   row; list header "Last updated: 2026-03-04 14:28:39 UTC"). N1 has very low practical
   coverage; this is a stated limitation, not a tuning target.
2. **Gate techniques in gate 2 (§4.6).** A development file matches a rule when one of the
   rule's gate techniques equals one of the file's expected techniques **exactly**; a parent
   technique never matches its sub-techniques or the reverse. Gate techniques are the §5 map
   and nothing else: **N5 `T1568.002`, N7 `T1571`, N8 `T1071.004`**. N1, N2, N3, N4, N6 and N9
   have no gate technique. "Alerts on a file" means at least one alert when that file is
   imported on its own.
3. **Expected-detection manifest.** It is
   `evaluation/reports/2026-11-network-windows-v1/expected_detections.json` (built by
   `evaluation/network_expected_detections.py` from the host engine's frozen path-only
   technique manifest and the §5 map; no sample was parsed), frozen with this rule. **No rule
   has an expected sample** in either half. Therefore every rule that ships passes gate 2 only
   through its invented positive and negative tests and ships **`unvalidated_on_samples`, with
   confidence capped at `single_signal`** (§6.3). The report half of the samples (§4.8, §4.9 a)
   is still measured and reported, with no expected file.
4. **Popular list.** "Popular" (§2.1) uses exactly the local Tranco snapshot
   `data/raw/tranco_final_approved.csv` with SHA-256
   `bd231a8e583dfd379b89a2b30396cdd1866ac1dc71684441f80a1069e1d78d9e` (378,795 bytes, as
   recorded in `evaluation/reports/2026-10-v4/data_hygiene.json`). A measurement with a
   different or missing file stops before any rule runs.
5. **Code and inputs.** Measurement uses the readers, detections, blocklist loader, engine,
   requirements and inputs at the SHA-256 values recorded in `FREEZE.json`. Any change to them
   before a measurement is a dated pre-result amendment (§4.10).

## 5. ATT&CK v20.0

Checked on 26 November 2026, read-only, against the pinned
`enterprise-attack-20.0.json` (size and SHA-256 match `data/attack-lock.json`, prefix
`2339a3c36353`; the file was read from the main ETIS checkout because this worktree has no
`data/external/`, and was not modified). Every id below exists and is neither revoked nor
deprecated.

| When | Technique | Tactic (v20.0) | Basis |
| --- | --- | --- | --- |
| N5 burst (`dga_nxdomain_burst`) | `T1568.002` Domain Generation Algorithms | command-and-control | Many algorithm-like names failing to resolve is the observable pattern of DGA. A single DGA-like name (`dga_like_domain`) maps to nothing. |
| N8 with two or more signs, or `dns_txt_burst` with another sign | `T1071.004` Application Layer Protocol: DNS | command-and-control | Data-carrying query patterns observed in the DNS log. One sign alone maps to nothing. |
| N7 together with N1 or N6 for the same destination | `T1571` Non-Standard Port | command-and-control | A port outside the fixed set used for a destination already judged C2-like. N7 alone maps to nothing (many legitimate applications use other ports). |

**Not mapped (dishonest from these logs):**
- N1/N2/N3 list hits: a list hit says a destination is listed, not which technique was used.
  `T1071` Application Layer Protocol, `T1095`, `T1573` Encrypted Channel are not observable
  without protocol or payload data.
- N6 beaconing alone: updaters and sync clients beacon; `T1071`/`T1029` are not observed.
- N3/N4 phishing-domain lookups: `T1566.002` Spearphishing Link and `T1204.001` Malicious
  Link need evidence of delivery or a click; a DNS query is neither. The phishing incident the
  Finding joins already carries its own mapping.
- N9 rare destinations; `T1105`, `T1572`, `T1090`, `T1041`, `T1048.003`: transfer,
  tunnelling, proxying or exfiltration are not observable from these logs.

Checked and present (all active), listed so the reviewer can see the alternatives considered:
`T1071`, `T1071.001`, `T1071.004`, `T1568`, `T1568.002`, `T1571`, `T1048`, `T1048.003`,
`T1573`, `T1095`, `T1029`, `T1204.001`, `T1566.002`, `T1105`, `T1132`, `T1572`, `T1090`,
`T1001`, `T1041`, `T1583.001`, `T1102`. `record_findings` validates every emitted id against
the local catalogue.

## 6. Findings

### 6.1 Unit and identity

Matches are grouped per (detection, `device_ref`, destination key, fixed UTC hour of the
first event) into **one Finding**; the destination key is the registered-domain hash or the
remote-IP hash (for N5 bursts and N8, the registered domain). Engine `network.windows`,
version `netwin-v1+rules:<manifest sha256 prefix>+lists:<lock sha256 prefix|none>+url:<url
candidate id|none>`; observation kind `windows_network_batch`; domain `network`; source
`{kind: import, ref: network_windows_imports:<id>}`; `observed_at` is the first matching
event's time.

### 6.2 Kinds and severity

| Detection | Kind | Severity |
| --- | --- | --- |
| N1 allowed connection | `known_bad_destination` | high |
| N1 dropped connection | `known_bad_destination` | medium |
| N1 DNS answer only | `known_bad_destination` | medium |
| N2 | `known_bad_destination` | medium; **high** if an allowed connection to an answer IP of that name follows within 1 h |
| N3 | `phishing_domain_lookup` | medium |
| N4 alone | `phishing_domain_lookup` | low; never above medium, only through combination |
| N5 `dga_like_domain` | `suspicious_domain` | low |
| N5 `dga_nxdomain_burst` | `suspicious_domain` | medium |
| N6 | `beaconing` | low; **medium** with N5 or N9 for the same destination; **high** with N1 or N2 |
| N7 | `unusual_port` | low; **medium** with N6 for the same destination |
| N8 one sign | `dns_tunnelling_signs` | low |
| N8 two or more signs | `dns_tunnelling_signs` | medium |
| N9 | `rare_destination` | info |

When several detections fire for one destination in the same hour, each keeps its own
Finding and kind; the combination only raises severity as in the table. Severity is a fixed
table, never derived from a score.

### 6.3 Confidence (categorical)

Detections fall into independent families: **lists** (N1, N2, N3), **model** (N4),
**lexical** (N5, N8), **behavioural** (N6, N7, N9).

| Condition | Confidence |
| --- | --- |
| Detections from two different families agree on the same device, destination and hour | corroborated |
| A single detection, or several from one family | single_signal |
| N4 alone (model used outside its training input) | undetermined |
| A rule shipped `unvalidated_on_samples` | at most single_signal |
| The coverage lacks the source that would show whether a connection happened (for example N1 answer-only with no firewall, Sysmon 3 or snapshot source) | undetermined |

`confirmed` is never used: ETIS cannot establish ground truth on the user's PC.

### 6.4 Indicators (hash only, core v1 §2.3)

| Type | From | Role |
| --- | --- | --- |
| `ip` | Remote non-local IP of alerted connections or alerted DNS answers | `remote_endpoint` |
| `domain` | Registered domain of alerted DNS queries, with `registered_domain_hash` | `resolved_name` |
| `hash` | SHA-256 from Sysmon 1 `Hashes` of the process that made an alerted Sysmon 3 connection or Sysmon 22 query, joined by `ProcessGuid` **within the same import** only | `connecting_process` |

All indicators are sent hash-only (`value=None`); if the same hash already exists with a
plaintext feed value, the finding links to that row (core v1 §2.3). At most 50 indicators per
Finding. For N8 only the registered domain is an indicator, never the query names, which may
carry tunnelled data. Local addresses, device names, user names and process paths are never
indicators.

### 6.5 Evidence details and pseudonyms

- `device_ref`: HMAC-SHA-256 of the computer name with the host engine's key
  (`ETIS_HOST_PSEUDONYM_KEY`) and the host engine's normalisation, so it equals the host
  engine's `host_ref` for the same PC. For sources without a computer name (firewall log,
  snapshots), the import uses the name given by `--device-name`, defaulting to the local
  computer's name when the import runs on the PC that produced the files; the name itself is
  never stored.
- `account_ref` (Sysmon `User` only): the host engine's account pseudonym.
- Details: detection id and reason codes; counts (events, distinct names or ports, gaps);
  window start and end; for N6 median gap, dispersion and event count; for N5/N8 the label
  length, entropy and sign values as numbers; for N7 the port **number** (a port is not
  personal data) and `baseline: 24h|none`; for N4 the score and the frozen threshold; list
  attribution for N1/N2 (list name, version, licence, link); coverage flags; the import's
  input file SHA-256s; process category `known_process_hash`/`unknown` (never a process name
  or path).
- Never: domain or host names in clear (they are indicators, hash-only), IPs, local ports,
  query names, process names or paths, user or computer names.

### 6.6 Correlation on the same device and with other engines

Findings go through the unchanged `record_findings`:

- `domain` pivot: a phishing SMS or URL scan's link host → the PC later queries that
  registered domain (N3) → **same incident**. Core exclusions apply.
- `ip` pivot: a `network.windows` remote endpoint equal to a `network.flows` or host engine
  (Sysmon 3, RDP source) `remote_endpoint` → same incident.
- `hash` pivot: the `connecting_process` hash equals a malware engine `scanned_file` hash or a
  host engine `executed_file` hash → same incident ("this file was flagged", "it ran", "it
  talked to this destination").
- **Same device without a shared indicator:** `device_ref` equals the host engine's
  `host_ref`, so the console can show host and network Findings of one PC side by side. As in
  host-engine-v1 §6.6, local pseudonyms never pivot incidents: two unrelated events on one PC
  are not one incident just because they share a device.
- Low and info Findings never open incidents (core v1 §3.2).

### 6.7 Console and API (read-only)

- `GET /network/windows/imports` (paginated: time span, sources present, counts per source
  and event id, coverage, Findings by kind), `GET /network/windows/imports/{id}` (the import
  with its Findings: kind, severity, confidence, reason codes, counts, device_ref, list
  attribution, ATT&CK ids, incident link), `GET /network/windows/health`. No upload,
  path or file parameter; no endpoint starts an import or changes a system setting.
- A **"Network (Windows)"** console tab, Arabic and English, following the File scans page:
  health banner, import list, coverage panel ("not visible" detections in their own colour),
  Finding cards, list attribution with links to the list pages, and a help panel describing
  how the owner can turn each source on (text only; commands shown as inert text).
  Destinations are shown only as hashes, or as the feed's plaintext where the indicator
  already exists from a feed.

### 6.8 Health

Health reports `rules_missing` (shipped-item manifest absent or not matching), `blocklists_missing`,
`blocklists_stale` (newest list older than 7 days; rules still run), `indicator_store_empty`,
`url_model_unavailable` (N4 skipped), `blocklist_source_stale` (informational: the list's own
"Last updated" header is older than 30 days; §2.2 note of 27 November 2026), or `available`, with
`blocklist_ages` (fetch age and source age in days). The engine registers when the shipped-item
manifest verifies; the list and model parts are optional.

## 7. Privacy

| Stored in the ETIS database | Never stored, never leaves the PC |
| --- | --- |
| Import record: input file SHA-256 and size, counts per source and event id, time span, coverage, manifest and list versions | The exported log files and snapshot files (read in place) |
| Findings with hash-only `ip`, `domain`, `hash` indicators | DNS query names, answers and connection records that did not alert; any per-destination history |
| `device_ref`, `account_ref` HMACs; port numbers and numeric rule values | Computer names, user names, process names and paths, local IPs and ports |
| Rule ids, reason codes, list attribution | The in-memory records (destroyed when the import ends) |

- **No full browsing history:** DNS and connection logs are browsing history. Non-alerting
  records are counted and discarded. The N7 and N9 baselines exist only in memory for one
  import; v1 keeps no destination history across imports (a cross-import baseline would
  store a hashed history and is out of scope).
- Unkeyed SHA-256 of a domain or IPv4 address is easy to reverse. That is accepted only for
  **alerted remote** destinations, where joining with feed and phishing indicators is the
  purpose, as `network.flows` §6.
- Nothing is sent to any service. No lookup of any kind.
- Logs record reason codes and counts only.
- Import-derived Findings expire after `ETIS_NETWORK_RETENTION_DAYS` (default 30), shared with
  `network.flows`, with the core orphan-indicator clean-up and `findings_expired` events (as
  the malware engine's retention, which extends `data/scripts/retention.py`).
- The import command warns that exported DNS and firewall logs are personal data, to be kept
  private and never shared.

## 8. Test plan

All tests use invented records generated at test time; no real log is committed.

1. **Readers:** DNS EVTX through the existing reader with the test-only EVTX writer; firewall
   text with `#Fields:` header, unknown header refused, malformed lines counted; Sysmon 3/22/1;
   snapshot JSON lines; limits enforced; locality rules.
2. **Snapshot command:** runs with the connection-table calls replaced by fakes; writes only
   under the ignored folder; never calls anything that kills, blocks or connects.
3. **Detections:** table-driven positives and negatives at each constant (9 vs 10 events,
   gap dispersion 0.10 vs 0.11, label length 9 vs 10, entropy 3.49 vs 3.5, 19 vs 20 TXT
   queries, 49 vs 50 labels, 119 vs 120 characters, ports in and out of the set, baseline 47 h
   vs 48 h, popular vs not popular, local destinations ignored).
4. **Lists:** invented list files pinned by size and SHA-256; mismatch refused with a reason
   code; exact matching only; attribution block present on every list Finding.
5. **N4:** the frozen URL artifact and threshold are loaded read-only and asserted unchanged
   (hash and value); the model receives only `https://<name>/`; nothing is fetched.
6. **Selection rule:** gates, ⌊N/7⌋, shipped-set reduction order, `unvalidated_on_samples` cap,
   owner review labels and splits, `suspected_malicious` only with a recorded local security
   product detection — table-driven, before any measurement.
7. **Findings:** grouping, kinds, severity and confidence tables including families and
   combinations, indicators (local never emitted, N8 registered domain only, process hash only
   within one import), ATT&CK rules (no technique from a list hit, beaconing, a single DGA-like
   name or a single tunnelling sign; ids validated against the v20.0 fixture).
8. **Privacy:** marker strings in computer names, user names, process paths, query names and
   local addresses never reach Findings, indicators, events, import records, API responses or
   logs. HMACs are stable with one key and change with another; `device_ref` equals the host
   engine's `host_ref` for the same name.
9. **Correlation:** N3 joins an existing phishing incident by registered domain; a
   `connecting_process` hash joins a malware `scanned_file` incident; device refs never pivot;
   low and info open no incident.
10. **Read-only and no network:** import, engine and API run with sockets blocked; no API route
    accepts a body or path; no code path calls `wevtutil sl`, `netsh`, `Set-NetFirewallProfile`
    or the Task Scheduler.
11. **Retention:** old imports expire with their Findings and orphan indicators; feed rows stay.
12. **Regression:** the `/analyze` parity gate, the full suite, database initialisation,
    frontend build and lint pass at every commit.

## 9. Implementation steps (small commits)

Each commit runs pytest, database initialisation, frontend build and lint. Downloads need the
owner's explicit approval first. All steps run on Windows; none needs Linux.

| Step | Commit |
| --- | --- |
| 0 | `docs: network-lite windows engine design` (this document) |
| 1 | `feat: windows dns, firewall and sysmon network readers` (§8.1; invented fixtures) |
| 2 | `feat: local connection snapshot command` (§8.2; standard library only) |
| 3 | `feat: device pseudonyms and network coverage report` (reuses the host key) |
| 4 | `feat: network-lite detections N1-N9` (§8.3; invented records) |
| 5 | `chore: network blocklists fetch, lock and licence entries` (Feodo Tracker and SSL Blacklist only; formats per §11 L1–L2). **Done 27 November 2026 with Feodo Tracker alone** (§2.2 note) |
| 6 | `chore: network sample sources and expected-detection manifest` (only sources §11 S1–S3 confirm). **Done 27 November 2026:** `evaluation/reports/2026-11-network-windows-v1/expected_detections.json`, no rule has an expected sample |
| 7 | `docs: freeze network-windows selection rule` (§4 with SHA-256, before any measurement). **Done 27 November 2026:** `evaluation/reports/2026-11-network-windows-v1/` |
| 8 | `chore: owner-PC benign network aggregates` (owner turns sources on, waits, exports; aggregates only) |
| 9 | `feat: network-windows gates and shipped-item manifest` |
| 10 | `feat: network.windows engine` (grouping, severity, confidence, indicators, ATT&CK, registry, health) |
| 11 | `feat: migration for network windows imports and import command` (next free migration number; 008 at the time of writing) |
| 12 | `feat: retention for network windows import findings` |
| 13 | `feat: network windows API and console tab` (Arabic and English) |
| 14 | `docs: network-lite engine implementation notes` (README, LOCAL-IMPLEMENTATION, api-v2, data-licences, engine-authors) |

The sealed test (§4.9) is not a step of this plan.

## 10. Owner decisions (26 November 2026)

1. **Lists:** v1 uses **Feodo Tracker and SSL Blacklist only** (CC0, abuse.ch terms §3.4).
   URLhaus is free only for not-for-profit use under the abuse.ch terms §3.1–3.2 and is left
   for a later amendment; until then N2 is inactive.
2. **DNS Client log size:** raising the log's maximum size before the 14 device-days is
   **recommended as an owner action** (with administrator rights), so the export covers the
   whole period. ETIS never changes it; the import only reports the span actually covered.
3. **No destination history:** v1 keeps **no destination history between imports**, hashed
   or otherwise. The N7 and N9 baselines exist only in memory within one import (§7).

## 11. To verify (before the step that depends on it)

| # | Item | Page to read | Needed by step |
| --- | --- | --- | --- |
| W1 | **Verified (26 November 2026, provider manifest read locally, read-only):** channel `Microsoft-Windows-DNS-Client/Operational`; 3006 "DNS query is called for the name %1, type %2, query options %3, …"; 3008 "DNS query is completed for the name %1, type %2, query options %3 with status %4 Results %5"; 3020 versions 0–2 "Query response for name %1, type %2, … returned %5 with results %6[, client PID %7]". 3008 and 3020 carry the answers (`QueryResults`). No Microsoft Learn page for these events was identified. | `wevtutil gp Microsoft-Windows-DNS-Client /ge /gm:true` and `Get-WinEvent -ListProvider Microsoft-Windows-DNS-Client` (templates) | 1 |
| W2 | **Verified (26 November 2026):** template fields 3006 `QueryName, QueryType, QueryOptions, ServerList, IsNetworkQuery, NetworkQueryIndex, InterfaceIndex, IsAsyncQuery`; 3008 `QueryName, QueryType, QueryOptions, QueryStatus, QueryResults`; 3020 `QueryName, QueryType, NetworkIndex, InterfaceIndex, Status, QueryResults` (+ `ClientPID` v1, + `QueryBlob` v2) (provider manifest). 9003 = `DNS_ERROR_RCODE_NAME_ERROR` "DNS name does not exist."; note 9714 `DNS_ERROR_NAME_DOES_NOT_EXIST` has the same wording, and 9501 `DNS_INFO_NO_RECORDS` "No records found for given DNS query." (System Error Codes 9000–11999). **Still to verify:** the text format of `QueryResults` (the reader keeps only tokens that parse as IPs) and which of 9003/9714 the client logs for a non-existent name. | Provider manifest; https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--9000-11999- | 1, 4 |
| W3 | **Verified (wevtutil page):** `sl` "/e … Enables or disables a log"; "/ms … Sets the maximum size of the log in bytes. The minimum log size is 1048576 bytes (1024KB) and log files are always multiples of 64KB"; `epl` exports a log to a file. **Still to verify:** that the DNS Client log is off by default, its default maximum size, and whether cached answers are logged (the page does not say). | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil | 8 |
| W4 | **Verified (logging page):** "No logging occurs until you set one of following two options" (*Log dropped packets*, *Log successful connections*); "The default path for the log is `%windir%\system32\logfiles\firewall\pfirewall.log`"; "The default maximum file size for the log is 4,096 kilobytes (KB)"; "The maximum log size is 32,767 KB (32 MB)"; settings are per profile (Domain, Private, Public); a custom location must let the Windows Firewall service write to it. | https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging | 8 |
| W5 | **To verify (the logging page does not document the format):** `#Fields:` header, field list, `#Time Format` values and time zone of `date`/`time`, `pid` field on current Windows 11 builds. The step 1 reader is therefore header-driven: it refuses unknown header directives and field names, requires `date time action protocol src-ip dst-ip src-port dst-port path`, treats `#Time Format: Local` (or none) as the importing PC's zone unless a zone is given, and reports the basis used. | A log produced on the owner's PC (owner reads its header) | 1 |
| W6 | `Set-NetFirewallProfile` parameters `-LogAllowed`, `-LogBlocked`, `-LogMaxSizeKilobytes`, `-LogFileName` | learn.microsoft.com/powershell/module/netsecurity/set-netfirewallprofile | 8 (owner instructions) |
| W7 | `netsh advfirewall set allprofiles logging ...` syntax | learn.microsoft.com netsh advfirewall reference | 8 (owner instructions) |
| W8 | **Verified (Sysmon page):** "The network connection event logs TCP/UDP connections on the machine. It is disabled by default."; "Each connection is linked to a process through the `ProcessId` and `ProcessGuid` fields"; events go to `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`; process creation carries `ProcessGUID` and a file hash per `HashType`. **Still to verify:** the other event 3 field names (`Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationHostname`, `DestinationPort`) and the event 1 `Hashes` field name; the page does not list them and says `sysmon -s` prints the schema (Sysmon is not installed on the owner's PC, so it was not run). The reader counts and skips a record that lacks a required field. | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | 1 |
| W9 | **Verified (Sysmon page):** event 22 "is generated when a process executes a DNS query, whether the result is successful or fails, cached or not"; "added for Windows 8.1". **Still to verify:** its field names (`QueryName`, `QueryStatus`, `QueryResults`, `Image`) and whether it has a query type (the page names none; the reader records no type for event 22, so the TXT part of N8 is not visible from Sysmon). | Same page | 1, 4 |
| W10 | **Verified (licence page):** "You may install and use any number of copies of the software on your devices"; no term restricts analysing the output; it warns that files saved by the tools "may include personally identifiable or other sensitive information". ETIS only reads exported Sysmon logs; it neither ships nor installs Sysmon. The Sysmon page itself names no licence. | https://learn.microsoft.com/en-us/sysinternals/license-terms | 1 |
| W11 | **Verified (26 November 2026):** `GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)` returns `ERROR_INSUFFICIENT_BUFFER` with the needed size in `pdwSize`; Iphlpapi.dll. `MIB_TCPROW_OWNER_PID` = `dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid`, ports "in network byte order"; `MIB_TCP6ROW_OWNER_PID` = `ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid`; states 1 (CLOSED) … 12 (DELETE_TCB). **Still to verify:** the numeric value of `TCP_TABLE_OWNER_PID_ALL` (5 assumed; the `TCP_TABLE_CLASS` page returned 404, so the parser refuses rows that do not match the documented layout) and whether rights are needed (the pages do not say). UDP endpoints are not read in v1: they have no remote address. | https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable, .../api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid, .../api/tcpmib/ns-tcpmib-mib_tcp6row_owner_pid (updated 22 February 2024) | 2 |
| W12 | **Page read, fields not listed:** the `Get-NetTCPConnection` page lists only `CimInstance` as output; `LocalAddress`, `LocalPort`, `RemoteAddress`, `RemotePort`, `State`, `OwningProcess` appear only as filter parameters. Owner documentation only; the snapshot command does not use it. | https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection (updated 14 May 2025) | 2 |
| W13 | **Verified (repository code, 26 November 2026):** `app.core.url_utils` builds `tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=False)`: no suffix-list URL and no cache, so only the bundled snapshot is used. The step 1 readers do not call it; they normalise names with `idna` only. | `backend/app/core/url_utils.py` | 1 |
| L1 | **Verified (27 November 2026, list page and file):** recommended list as plain text, JSON, McAfee and Palo Alto formats, "generated every 5 minutes"; 30-day CSV/JSON/txt, aggressive and Suricata/Snort variants; v1 uses the recommended plain text (one IP per line, `#` comments). At fetch time: 1 entry, own header "Last updated: 2026-03-04 14:28:39 UTC" (§2.2 note). CC0 re-read 27 November 2026, terms §3.4. | https://feodotracker.abuse.ch/blocklist/ | 5 |
| L2 | **Verified (27 November 2026):** the page still links the IP list (CSV and IPs only), but the file header says "This list has been deprecated on 2025-01-03" (last updated 2025-01-02, 0 rows). **Not used in v1** (§2.2 note). | https://sslbl.abuse.ch/blacklist/ | 5 |
| L3 | URLhaus: host-list format and matching unit (terms: not-for-profit, §3.1–3.2) | https://urlhaus.abuse.ch/api/ | only if a later amendment proposes it |
| L4 | ThreatFox and any other feed: terms | the feed's own terms page | only if proposed |
| L5 | Local Tranco snapshot: list date and licence (recorded in `docs/data-licences.md` as not established) | https://tranco-list.eu/ and the repository entry | 4 |
| S1 | **Done (27 November 2026), by the host method (host-engine-v1 §3.2, §4.7 item 3):** expected detections come from the host engine's frozen path-only technique manifest and the §5 map (gate techniques N5 `T1568.002`, N7 `T1571`, N8 `T1071.004`; exact match); no sample was parsed. No sample carries a gate technique, so **no rule has an expected sample**; 9 samples carry §5 "not mapped" techniques (`T1572`, `T1090.001`, `T1105`), listed without obligation. All 280 pinned files verified read-only (size, SHA-256). Which files contain events 3/22 was deliberately not inspected. | `evaluation/reports/2026-11-network-windows-v1/` | 6 |
| S2 | **Verified (27 November 2026):** hosted on Mendeley Data (DOI 10.17632/y8ph45msv8.1), not Zenodo; licence shown "MIT"; over 30 million domains of 50 malware variants as TXT lists, ARFF/CSV features, and DGA executables and source. **Not used: contains executables** (owner decision). | https://data.mendeley.com/datasets/y8ph45msv8/1 and the Data in Brief article (PMC7090278) | 6 |
| S3 | **Searched (27 November 2026): none found.** Public DNS-tunnelling datasets (for example CTU DNS-Threats, Mendeley tunnelling query sets) are PCAP or CSV, which v1 does not read. N8 has no sample. | web search | 6 |

## Sources

Read for step 1 on 26 November 2026 (sources of the W-items marked **verified** in §11):

- DNS Client provider manifest on the owner's PC, read-only: `wevtutil gp Microsoft-Windows-DNS-Client /ge /gm:true` and `Get-WinEvent -ListProvider Microsoft-Windows-DNS-Client` (event templates). No log was enabled, exported or read. (W1–W2)
- System Error Codes (9000-11999), https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--9000-11999- (page updated 16 July 2025). (W2)
- wevtutil, https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil (page updated 15 May 2026). (W3)
- Configure Windows Firewall logging, https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging (page updated 8 October 2026). (W4; it does not document the log format, W5)
- Sysmon, https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon (published 10 September 2026). (W8–W9)
- Sysinternals Software License Terms, https://learn.microsoft.com/en-us/sysinternals/license-terms (page updated 24 May 2023). (W10)
- Sysmon provider manifest: not registered on the owner's PC (`Get-WinEvent -ListProvider Microsoft-Windows-Sysmon` found none), so the Sysmon field names stay to verify.

Read by the reviewer on 25 November 2026 (the only source behind a **verified** fact here):

- abuse.ch terms of use, https://abuse.ch/terms-of-use/ §3.4: "Feodo Tracker, SSL Blacklist, and YARAify are free to use without limitations according to Creative Commons principles (CC0)" (§2.2); §3.1–3.2 not-for-profit terms (URLhaus, §10).

Repository material read for this design:

- [Host engine v1 design](host-engine-v1.md) and [network engine v1 design](network-engine-v1.md) in this repository (structure, privacy, evaluation style, amendment 3).
- [Malware engine v1 design](malware-engine-v1.md) §3.4 (abuse.ch terms reading of 25 November 2026).
- `docs/data-licences.md` (Tranco, EVTX-ATTACK-SAMPLES entries).
- The local, hash-verified `enterprise-attack-20.0.json` (ATT&CK ids in §5), read read-only.

Apart from the pages listed above, no external page was read for this design; every other
Windows, Sysmon, list and sample fact is therefore **to verify** at the page named in §11.
