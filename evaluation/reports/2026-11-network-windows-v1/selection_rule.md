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

