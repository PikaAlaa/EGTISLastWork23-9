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

### 4.7 Pre-measurement clarifications (amendment 2, 24 November 2026)

Written before any rule was run on any attack sample or benign log, to remove choices that
would otherwise be made after seeing results. They take precedence over §4.1–4.6 where
those are silent or ambiguous.

1. **Counting unit.** An "alert" in gates 1 and 3 is one grouped Finding as §6.1 defines
   it: one per detection or Sigma rule, host reference, account reference (where the
   detection has one) and fixed UTC clock hour of the first matching event.
2. **Level in gate 3.** A rule's base level: native rules as in §6.2 without combination
   escalation (native H6 and H7 are `low` and are not counted); Sigma rules by their
   `level`.
3. **Technique matching in gate 2.** A development file matches a rule when one of the
   rule's gate techniques equals one of the file's manifest techniques exactly; a parent
   technique never matches its sub-techniques or the reverse. Gate techniques: for native
   rules the primary technique only — H1 `T1110.001`, H2 `T1110.003`, H3 `T1136.001`, H4
   `T1098.007`, H6 `T1543.003`, H7 `T1053.005`, H8 `T1685.005` and `T1685.001`, H9 `T1133`,
   H10 `T1685`, H11 `T1204.002`, H12 `T1490`, H13 `T1134.002`; secondary tags create no
   obligation. For Sigma rules, every target-set technique left after remapping. "Alerts
   on a file" means at least one alert when that file is imported on its own. A rule that
   fails gate 2 is not shipped.
4. **Imports.** Each attack-sample file is its own import (H13 therefore runs with
   `baseline: none` on samples). Files with identical content are one sample. The owner's
   exported files are imported together as one import.
5. **Gate 4.** If the CPU limit fails, nothing ships; no rule is removed automatically. A
   dated, owner-approved amendment is required before any re-measurement.
6. **Sigma pool details.** The pool is fixed by `data/sigma-lock.json` (release
   `r2026-07-01`, package `sigma_all_rules.zip`). `process_creation` rules are converted
   for both Sysmon 1 and Security 4688. "Names fields ETIS never produces" means any field
   name that is not a plain Windows field name (letters, digits and underscore; for
   example a log shipper's dotted JSON path). Correlation rules are excluded.
7. **Technique manifest.** `evaluation/reports/2026-11-host-v1/technique_manifest.json`,
   built only from sample paths by the fixed keyword table in
   `evaluation/host_technique_manifest.py` (no sample opened), is frozen together with
   this rule. Samples it cannot label are excluded and counted.

### 4.8 Per-rule owner review (amendment 3, 24 November 2026)

Dated pre-result amendment, approved by the owner and written before any rule was run on
any benign log or attack sample. It amends the rule frozen as `selection_rule.md` with
SHA-256 `deece958a570ef97790029bf312164de85636e9d98eedb7951e08af94d0449ab`. It replaces the
per-alert labelling of §4.4 with per-rule labelling:

1. **Review unit.** The owner reviews alerts per rule, not per alert. For each rule that
   alerted on the owner's PC, the owner sees a summary (number of alerts, host-days with
   alerts, alerts outside host-days, level, techniques and the most frequent values of the
   matched events' fields) and up to 10 example alerts. Examples are chosen without
   judgement: all alerts if there are 10 or fewer, otherwise 10 spread evenly over the
   rule's alerts in time order (first and last included).
2. **Local only.** The summary and examples are shown only on the owner's PC, from ignored
   `evaluation/local-results/host-v1/`, and are never committed, uploaded or shared.
3. **One label per rule.** The owner gives one label — `benign_explained`, `unexplained`
   or `suspected_malicious` — that applies to all of that rule's alerts.
4. **Split.** If a rule's alerts differ, the owner may split them into groups by alert
   number and give each group one label. Only the number of alerts per label is committed.
5. **Gate counting is unchanged.** Each alert takes its rule's (or group's) label, and
   §4.4, §4.5 and §4.7 count it exactly as before.

