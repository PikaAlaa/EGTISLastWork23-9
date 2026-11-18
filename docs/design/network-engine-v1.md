# Network engine v1 (`network.flows`) — design

Status: **design only** (18 November 2026), branch `feat/network-design`. No code, no
dataset download, no training and no evaluation accompany this document.

`network.flows` is ETIS's first non-phishing engine. It reads flow records from the
user's own network, scores them with a locally trained model, and emits `finding-v1`
Findings through the core v1 path ([core v1](core-v1.md) §1, §8;
[engine authors](../engine-authors.md)). It never touches `/analyze`, its thresholds or
any frozen phishing model.

## 0. Constraints

| Constraint | How this design keeps it |
| --- | --- |
| Free and local only | Zeek (open source) and Python run on the user's PC. No cloud, paid service or hosting. |
| Nothing leaves the PC | Captures and logs are read in place. No upload service, no external enrichment, no IP/domain lookup, no resolution or connection to any observed address. |
| Indicators are inert | Remote IPs and domains are hashed, displayed as plain text only when already public (feed) and never contacted. |
| Phishing path unchanged | Separate engine, separate model and data. The `/analyze` parity gate keeps running. |
| Data licences | Training data stays under an ignored directory and is never redistributed; `docs/data-licences.md` gets an entry before acquisition (§2.5). |
| No sealed test | The held-out capture day is reserved; it is not run during implementation (§4.8). |
| Honest claims | UNSW-NB15 is a 2015 laboratory testbed. Results are exposed development evidence and do not establish detection accuracy on Egyptian or any real network. |

## 1. Input from the user's own network

### 1.1 Accepted input

| Input | v1 | Notes |
| --- | --- | --- |
| Zeek `conn.log` (TSV with `#fields` header, or JSON lines) | **Primary** | Produced by the user's own Zeek, on their own network. |
| Zeek `dns.log` (optional, same capture) | Enrichment only | Maps responder IPs to queried names, to emit `domain` indicators (§5.4). Never a model feature. |
| PCAP / PCAPNG | Only when a local Zeek is configured | ETIS runs `zeek -C -r <file>` with a pinned local script into a temporary directory, then reads `conn.log`/`dns.log`. Without `ETIS_ZEEK_PATH`, ETIS refuses PCAP and explains how to produce `conn.log`. |
| NetFlow/IPFIX, CICFlowMeter CSV, live capture | Not in v1 | No live sniffing; no other flow formats. |

Limits: 1,000,000 conn rows and 500 MB per import (configurable), checked before parsing.

### 1.2 How the user supplies it

v1 uses a **local command**, not a browser upload:

```
python data/scripts/import_network.py --conn path\to\conn.log [--dns path\to\dns.log] [--local-net 192.168.1.0/24]
python data/scripts/import_network.py --pcap path\to\capture.pcap      # requires ETIS_ZEEK_PATH
```

The file is read where it is; ETIS does not copy it. A PCAP conversion writes only to
`var/tmp/network-<random>/` and deletes it when the import ends, successfully or not. The
console shows the results read-only (§5.6). Browser upload is deferred: the proxy's 32 KB
body limit is intentional, and moving large captures through it is not needed for v1.

### 1.3 The flow tool: Zeek

[Zeek](https://docs.zeek.org/en/current/quickstart) is free, open source (BSD-style
licence, to be confirmed from `COPYING` at the pinned tag before documenting it in
`docs/data-licences.md`) and reads PCAP offline with `-r`, without network access. Its
`conn.log` records each connection with `duration`, `orig_bytes`/`resp_bytes`,
`conn_state`, `history`, packet counts and IP byte counts
([conn.log reference](https://docs.zeek.org/logs/conn.html)). `orig_ip_bytes`/`resp_ip_bytes`
require `use_conn_size_analyzer = T`, which is the default and is pinned in the ETIS script.

Windows: Zeek has an official but limited native Windows build focused on PCAP-file
processing ([Zeek on Windows](https://zeek.org/2022/11/zeek-on-windows/)). The supported
routes are: (a) the user's existing Zeek sensor (Linux), (b) Zeek in WSL, (c) the native
Windows build. **The same Zeek version must produce training and runtime features.** ETIS
pins one version (recorded in the training manifest), runs `zeek --version` when it
converts a PCAP, and reads the conn.log header. A different or unknown version is
recorded as `feature_parity: unverified` and lowers confidence (§5.3).

### 1.4 Features (identical in training and use)

One module, `app/engines/network/features.py`, computes features from conn.log rows. The
training pipeline imports this exact module; there is no second implementation.

Per-connection fields (from conn.log): `proto`, `service` (Zeek's protocol detection,
categorical, unknown as `-`), `duration`, `orig_bytes`, `resp_bytes`, `missed_bytes`,
`orig_pkts`, `resp_pkts`, `orig_ip_bytes`, `resp_ip_bytes`, `conn_state` (categorical),
`history` (counts of each history letter, with case for direction).

Derived per connection: `log1p` of byte/packet counts, bytes per packet in each
direction, `resp_bytes / (orig_bytes + 1)`, packets per second.

**Causal window aggregates** (only earlier rows, 60-second window, same import): for the
originator host — connections, distinct responder hosts, distinct responder ports, share
of `S0`/`REJ`/`RSTO*` states; for the responder host — connections and distinct
originators (fan-in). Windows never cross an import boundary or a split boundary (§4.3).

**Excluded from features (frozen):** IP addresses and subnets, source and destination
port numbers, `uid`, timestamps, `local_orig`/`local_resp`, tunnel and VLAN fields. In
the training data, addresses and some header values identify testbed machines rather
than behaviour, so they are excluded to stop the model learning the laboratory layout.
The responder port is represented only through Zeek's `service` field and the window
"distinct ports" counts.

## 2. Training dataset

### 2.1 Requirement

The dataset must provide **raw packet captures** and **labels that do not depend on a
particular feature extractor**, so ETIS can run its pinned Zeek and its own feature code on
the training traffic and then attach labels. Pre-computed CSV features from another tool
cannot be used directly, because the user's input will not contain them.

### 2.2 Comparison

| | UNSW-NB15 | CIC-IDS2017 | CSE-CIC-IDS2018 |
| --- | --- | --- | --- |
| Origin | UNSW Canberra Cyber Range Lab; IXIA PerfectStorm traffic generator | Canadian Institute for Cybersecurity (UNB), 5-day lab, July 2017 | CIC and CSE, AWS-hosted lab |
| Raw PCAP | Yes, about 100 GB, split by the two simulation dates (22-1-2015, 17-2-2015) | Yes, about 51 GB (Mon–Fri, Monday benign only) | Reported to be distributed through AWS; not checked for this design |
| Labels | 2,540,044 records in four CSVs, plus a separate **ground-truth table** (`UNSW-NB15_GT.csv`) listing attack events with times and endpoints | Labelled flows exist only as CICFlowMeter output (`GeneratedLabelledFlows`, `MachineLearningCSV`) | CICFlowMeter output |
| Feature parity with Zeek input | **Good.** Ground truth is keyed by endpoints and time, so Zeek conn records from the raw PCAP can be labelled directly. The published features themselves came partly from Bro (Zeek's former name) and Argus. | **Poor.** Labels are attached to CICFlowMeter flows. Re-labelling Zeek flows means matching them to flows from a tool with documented bugs. Using CICFlowMeter at runtime instead would require users to run that Java tool, and the fixed and original versions produce different flows. | **Poor**, for the same reasons; the CICFlowMeter issue is reported as still present in 2018. |
| Size | 2.54 M records, 49 published features | More than 80 CICFlowMeter features per flow (flow count not stated on the official page) | Larger than 2017 |
| Licence/terms (official page) | "Free use … for academic research purposes is hereby granted in perpetuity." "Use for commercial purposes should be agreed by the authors." An older UNSW record said commercial use is prohibited. Citation required. | Data "are publicly available for researchers"; users "should cite our related paper". No explicit licence grant for redistribution or commercial use. | Same CIC style (not re-read for this design). |
| Known label problems | No published large-scale relabelling found in this review — **not** evidence that none exist. Precautions: the `Generic` category's meaning is unclear; testbed addresses and header values can act as shortcuts (excluded, §1.4); duplicates must be measured (§4.3). | Engelen, Rimmer and Joosen (2021) found errors in traffic generation, flow construction, feature extraction and labelling; more than 20% of original traces were reconstructed or relabelled. Lanvin et al. (2022) and Liu, Engelen et al. (2022) document further labelling errors. | Liu, Engelen et al. (2022) report many errors in 2018 too. |
| Classes | Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms, plus normal | Brute force (FTP/SSH), DoS/DDoS, Heartbleed, web attacks, infiltration, botnet, port scan | Similar |

### 2.3 Choice: UNSW-NB15

1. **Feature parity.** Its ground-truth table is independent of any feature extractor, so
   ETIS can produce training features with the same pinned Zeek and the same Python module
   that users run. CIC labels are bound to CICFlowMeter flows with documented errors.
2. **Two separate capture dates** give a time-separated reserved test (§4.3).
3. **Explicit academic-use grant.** ETIS is an academic graduation project. Commercial use
   or redistribution would need the authors' agreement; neither is planned.

Accepted weaknesses, stated in every report: 2015 synthetic traffic; no brute-force class;
`Generic` semantics unclear; about 100 GB of PCAP to process; a lab network that does not
resemble Egyptian home or office networks.

CIC-IDS2017 stays out of v1. It may later serve only as an exposed, labelled-with-caveats
robustness check after a separately frozen rule, never for selection.

### 2.4 Label join (frozen procedure)

1. Run the pinned Zeek over every UNSW PCAP with the ETIS script; keep `conn.log`.
2. Label a conn record as an attack when its 5-tuple (both directions) and protocol match a
   ground-truth event and its interval overlaps the event's start/end time, with a 1-second
   tolerance.
3. Several matching events of the same category: that category. Different categories:
   **drop** the record from training and evaluation and count it in the audit.
4. No match: normal.
5. Write an audit before any model fitting: match rates by category, dropped conflicts,
   unmatched ground-truth events, rows per capture file and duplicates.

### 2.5 Acquisition (later, with approval)

Nothing is downloaded by this design. A later step adds `data/scripts/fetch_unsw_nb15.py`
and `data/unsw-nb15-lock.json` (file names, sizes, SHA-256 measured at first download),
stores data under ignored `data/external/unsw-nb15/`, and adds a `docs/data-licences.md`
entry quoting the official terms above. The download needs the owner's explicit go-ahead
because of its size. If local storage is insufficient, a deterministic subset of PCAP files
(every k-th file per date, k declared in an amendment) is fixed **before any feature or
model result**. Trained weights derived from UNSW-NB15 stay under ignored
`release-artifacts/` until the team confirms they may be shared.

## 3. Attack classes and ATT&CK v20.0

Checked against the local, pinned `enterprise-attack-20.0.json` (all ids below exist and
are neither revoked nor deprecated).

### 3.1 Coarse classes

| ETIS class | UNSW categories | Kind | Notes |
| --- | --- | --- | --- |
| `reconnaissance` | Reconnaissance, Analysis | `network_reconnaissance` | Scanning and probing. |
| `denial_of_service` | DoS | `network_denial_of_service` | |
| `exploitation` | Exploits, Shellcode, Worms, Backdoors, Fuzzers | `network_exploitation` | Exploit delivery and attack payload traffic. |
| `other_malicious` | Generic | `network_suspicious_flow` | Counted as malicious for the binary detector; no technique (§3.2). |

### 3.2 Mapping table `net-map-v1`

Direction comes from the user's declared local networks (`--local-net`; RFC 1918,
loopback and link-local are local by default).

| Class | Condition | Technique | Name | Tactic |
| --- | --- | --- | --- | --- |
| reconnaissance | originator outside, responder local | `T1595` | Active Scanning | reconnaissance |
| reconnaissance | originator local | `T1046` | Network Service Discovery | discovery |
| denial_of_service | responder local | `T1498` | Network Denial of Service | impact |
| exploitation | originator outside, responder local | `T1190` | Exploit Public-Facing Application | initial-access |
| exploitation | originator and responder local | `T1210` | Exploitation of Remote Services | lateral-movement |
| exploitation | originator local, responder outside | none | — | outbound; recorded without a technique |
| other_malicious | any | none | — | `Generic` has no defensible mapping |

Sub-techniques (`T1595.001/.002`, `T1498.001`, `T1499.*`) are not used: flow records do
not distinguish them reliably. Brute force (`T1110`) is out of scope because UNSW-NB15 has
no brute-force class. `record_findings` still validates every id against the local
catalogue.

## 4. Frozen model-selection rule

This section is the rule. When implementation reaches selection, it is copied unchanged
into `evaluation/reports/<date>-network-v1/selection_rule.md` and its SHA-256 recorded
**before any model is fitted or any feature distribution is examined beyond the label
audit**. Any change after that is a dated pre-result amendment that cites the previous hash
and states that no candidate result has been seen. This is an exposed development
protocol on a laboratory dataset, not an independent final test.

### 4.1 Task

Binary detection per conn record (malicious vs normal). A second, separately reported
classifier assigns the coarse class (§3.1) to records the detector flags. Coarse class only
chooses the finding kind and ATT&CK mapping; it never creates an alert.

### 4.2 Candidates (fixed list)

| Id | Candidate | Fixed settings |
| --- | --- | --- |
| R0 | Rule baseline | Alert when, in the causal 60 s window, the originator has ≥ 20 distinct responder ports **or** ≥ 20 distinct responder hosts with ≥ 80% `S0`/`REJ`; **or** the responder receives ≥ 500 connections. Constants fixed here and never tuned. |
| LR | Logistic regression | Standardized features, one-hot categoricals, L2, `C ∈ {0.01, 0.1, 1, 10}`, balanced class weight. |
| RF | Random forest | 300 trees, `max_depth ∈ {12, None}`, `min_samples_leaf ∈ {1, 5}`, balanced class weight. |
| LGBM | LightGBM | `num_leaves ∈ {31, 63}`, `learning_rate ∈ {0.05, 0.1}`, 500 rounds with early stopping on calibration log-loss, balanced class weight. |

Seed 13 everywhere. The only hyperparameter choice is the listed grid, chosen by
calibration log-loss. No other candidates, features or data may be added without an amendment.

### 4.3 Splits (no leakage between flows of a capture or time window)

- **Reserved test:** every PCAP of the 17-2-2015 capture date. Not used for anything during
  implementation (§4.8).
- **Development:** the 22-1-2015 capture date, ordered by time and cut into contiguous
  blocks: first 70% of the capture time **train**, next 15% **calibration**, last 15%
  **validation**. A 5-minute buffer at each block boundary is discarded so no window
  aggregate or long connection spans two splits.
- Window aggregates are recomputed inside each split.
- Splits are written to a manifest (capture file, time range, row count, SHA-256) and
  committed before fitting.
- Exact duplicate feature rows across train and validation are counted and reported. They
  are not removed, so the measurement is not flattered.
- If an attack category is absent from a block, it is reported, not rebalanced.

### 4.4 Threshold

For each candidate except R0, choose on **calibration** the lowest score threshold whose
benign false-positive rate is ≤ 0.1% (flow level). Thresholds are then frozen; validation
never changes them.

### 4.5 Gates (validation, all must pass)

1. **False-alarm limit:** validation benign flow FPR ≤ 0.2%.
2. **Alert-volume limit:** ≤ 1 alerted record per 1,000 benign records in every 1-hour
   validation slice (catches bursts that a global rate hides).
3. **CPU latency limit:** scoring p95 ≤ 50 ms per batch of 1,000 pre-computed feature rows,
   2 threads, on the project PC, using the existing timing protocol style (warm-up, 30
   repeats, linear-interpolated p95). Feature extraction throughput is reported, not gated.

### 4.6 Selection

Among candidates passing every gate, pick the highest **validation attack recall** at the
frozen threshold. An ML candidate is selected only if its recall exceeds R0's by at least
**5 percentage points**; otherwise R0 is selected. Ties within 0.5 points go to the lower
validation FPR, then to the simpler candidate (R0 < LR < RF < LGBM). If no candidate passes
the gates, no network model is deployed and the engine is not registered.

### 4.7 Reported, never gating

Per-category recall; PR-AUC; Brier score; alerts per benign host-hour; the
duplicate count; the coarse-class macro-F1; an ablation without `service`; feature
importance; the label-join audit. All reports state that UNSW-NB15 is a 2015 lab testbed.

### 4.8 Reserved test

The 17-2-2015 run is a one-shot sealed test. It requires a target entry and supervisor
approval in `evaluation/targets.json` style, and the owner's explicit instruction. It is
**not** part of this implementation plan.

## 5. Findings, severity, confidence, indicators and correlation

### 5.1 Unit of a finding

Flagged records are grouped per (local host, coarse class, direction, 15-minute window)
into **one Finding**. Per-flow findings would flood incidents. The observation kind is
`zeek_conn_batch`; source is `{kind: import, ref: network_imports:<id>}`; engine
`network.flows`, version `net-v1+model:<artifact id>+zeek:<version>`.

### 5.2 Severity

| Class | Direction | Severity |
| --- | --- | --- |
| exploitation | inbound or internal | high |
| exploitation | outbound | medium |
| denial_of_service | responder local | high |
| reconnaissance | originator local (a local device scanning) | medium |
| reconnaissance | originator outside (internet background scanning) | low |
| other_malicious | any | low |

Severity is a fixed table, never derived from a score.

### 5.3 Confidence (categorical)

| Condition | Confidence |
| --- | --- |
| Feature parity unverified (§1.3) | undetermined |
| Selected model flags and R0 agrees, or a remote indicator matches an active feed indicator | corroborated |
| Selected model flags alone | single_signal |

`confirmed` is never used in v1: there is no confirmed ground truth for the user's network.

### 5.4 Indicators

- **Remote IP** of alerted flows: `ip` indicator, hash only, role `remote_endpoint`, at most 50 per finding.
- **Domain** for a remote IP, only from the same import's `dns.log` answers within the window:
  `domain` indicator with `registered_domain_hash`, hash only, role `resolved_name`.
- **Local hosts are never indicators.** A local device is referenced in
  `evidence.details.local_host_ref` as an HMAC-SHA-256 with a dedicated local key
  (`ETIS_NETWORK_PSEUDONYM_KEY`, generated by `scripts/initialize.py` into ignored `.env`).
  This groups a device's findings without storing its address, and stops every finding in
  one home network from correlating through the router's address.
- `evidence.details` holds: counts (records, flagged records, distinct remote hosts, distinct
  services), max and median score, threshold, class, direction, window start/end,
  `local_host_ref`, `feature_parity`, model id, Zeek version. Never addresses, ports per
  flow, payloads or file names.

### 5.5 Correlation with phishing incidents

Network findings go through the unchanged `record_findings`. Correlation pivots work as in
core v1:

- A `domain` indicator from `dns.log` shares a `registered_domain_hash` with a phishing
  finding's link host → **same incident**. Example: an SMS lure is scanned, and later the
  user's phone contacts that domain.
- An `ip` indicator matches a phishing URL whose host was that IP → same incident.
- Exclusions remain: shared hosting, official brand domains, official hotlines, analyst
  stoplist. Private and local addresses are never emitted (§5.4).
- Low-severity findings (internet scanning) never open incidents, as in core v1 §3.2.

The incident list already shows mixed domains. ATT&CK coverage gains Enterprise cells for
the §3.2 techniques without change.

### 5.6 Console and API (read-only in v1)

`GET /network/imports` and `GET /network/imports/{id}` (row counts, time range, Zeek
version, parity status, findings created) and a "Network imports" section in the
Incidents tab, Arabic and English. No upload endpoint in v1.

### 5.7 Health

`network.flows` registers only if the selected model artifact exists and its hash matches
the deployment metadata. Health reports `model_missing`, `zeek_not_configured` (PCAP
input unavailable; conn.log still works) or available.

## 6. Privacy

| Stored in the ETIS database | Never stored, never leaves the PC |
| --- | --- |
| Import record: input file SHA-256, size, row count, time range, Zeek version, model version, counts | The PCAP or log file (read in place), packet payloads |
| Findings with hashed remote IP/domain indicators | Local IP addresses (only keyed HMAC references) |
| `local_host_ref` HMACs | Ports and byte counts per flow (only window aggregates) |
| Aggregate counts and scores per finding | Temporary Zeek output (deleted after import) |

- Nothing is sent to any external service. No reverse DNS, WHOIS, geolocation or
  reputation lookup is performed. No observed address is contacted.
- Import-derived findings expire after `ETIS_NETWORK_RETENTION_DAYS` (default 30), with
  the same orphan-indicator clean-up and `findings_expired` events as scan retention.
- Logs record reason codes only: no paths, addresses or values.
- Unkeyed SHA-256 of IPv4 addresses is easy to reverse. That is accepted only for **remote**
  endpoints of flagged flows, where joining with feed and phishing indicators is the purpose;
  local addresses use the keyed HMAC.

## 7. Test plan

1. **Parser:** TSV and JSON conn.log, `#fields` header handling, unset `-`/empty values,
   malformed lines rejected with counts, size and row limits enforced before parsing.
   Invented logs only.
2. **Feature parity:** a committed tiny invented PCAP and its expected `conn.log` give
   identical feature rows through the PCAP path and the conn.log path. Training and runtime
   import the same module (asserted by identity).
3. **Causal windows:** no aggregate uses a later row; windows reset at import and split
   boundaries.
4. **Excluded features:** a test asserts no address, port, uid or timestamp column reaches
   the model matrix.
5. **Label join:** synthetic ground-truth table and conn rows cover match, overlap tolerance,
   conflicting categories (dropped) and the audit counts.
6. **Splits:** blocks are contiguous, buffers removed, no capture time in two splits,
   manifest hash stable.
7. **Selection rule:** table-driven tests of thresholding at FPR ≤ 0.1%, every gate, the
   5-point margin over R0, tie-breaks, and "no candidate passes → not deployed".
8. **Findings:** grouping into one finding per (host, class, direction, window);
   severity/confidence tables; `net-map-v1` ids exist in the v20.0 fixture; no technique for
   outbound exploitation or `Generic`.
9. **Privacy:** a marker test over findings, indicators, events, import records and logs;
   local addresses never appear as indicators; HMAC references are stable with the same key
   and change with another key; temporary directory deleted on success and failure.
10. **Correlation:** a network finding with a `dns.log` domain joins an existing phishing
    incident by registered domain; a private address never pivots; low severity opens no incident.
11. **No network access:** the import, PCAP conversion and engine run with sockets blocked
    in tests.
12. **Regression:** the `/analyze` parity gate, the full suite, database initialization,
    frontend build and lint pass at every commit.

## 8. Implementation order (small commits)

Each commit runs pytest, database initialization, frontend build and lint.

1. `feat: zeek conn.log and dns.log parsers` — limits, invented fixtures (§7.1).
2. `feat: network flow features with causal windows` — features module, exclusions (§7.2–7.4).
3. `chore: pinned zeek script and pcap conversion` — `ETIS_ZEEK_PATH`, version check, temp-dir clean-up, socket-blocked test.
4. `chore: UNSW-NB15 fetch script, lock and licence entry` — **download only after the owner approves**; checksums recorded at first download.
5. `feat: UNSW-NB15 label join and audit` — §2.4; audit report committed, data stays ignored.
6. `feat: network split manifest` — §4.3; manifest committed.
7. `docs: freeze network selection rule` — copy §4, record SHA-256, before any fit.
8. `feat: network candidate training and validation report` — R0/LR/RF/LGBM, thresholds,
   gates, selection; artifacts in ignored `release-artifacts/`; report committed.
9. `feat: network.flows engine and net-map-v1` — scoring, grouping, severity, confidence,
   indicators, HMAC references; registered only if a model was selected.
10. `feat: migration 007 network imports and import command` — `network_imports` table,
    pseudonym key in initialize.
11. `feat: retention for import-derived findings`.
12. `feat: network imports API and console section` — Arabic and English.
13. `docs: network engine v1 implementation notes` — README, LOCAL-IMPLEMENTATION,
    api-v2, engine-authors example.

## Sources checked for this design (18 November 2026)

- UNSW-NB15 official page (terms, size, tools, categories, ground truth): https://research.unsw.edu.au/projects/unsw-nb15-dataset
- UNSWorks record (older "commercial use prohibited" wording): https://unsworks.unsw.edu.au/items/4dc0e35c-6196-4c9d-945a-c50b981e5955
- UNSW-NB15 ReadMe (split by simulation dates 22-1-2015 and 17-2-2015): https://www.scribd.com/document/504374180/UNSW-NB15-Datasets-ReadMe
- CIC-IDS2017 official page (licence text, dates, attacks, PCAP sizes): https://www.unb.ca/cic/datasets/ids-2017.html
- Engelen, Rimmer, Joosen (2021), CICIDS2017 case study: https://researchportal.be/en/node/8038227 and https://lirias.kuleuven.be/retrieve/713070
- Lanvin et al. (2022), errors in CICIDS2017: https://hal.archives-ouvertes.fr/hal-03775466
- Liu, Engelen et al. (2022), error prevalence in CIC-IDS-2017 and CSE-CIC-IDS-2018: https://archive.cps-vo.org/node/97449
- Zeek conn.log reference: https://docs.zeek.org/logs/conn.html
- Zeek on Windows: https://zeek.org/2022/11/zeek-on-windows/

ATT&CK ids were checked against the local, hash-verified `data/external/attack/enterprise-attack-20.0.json`.
