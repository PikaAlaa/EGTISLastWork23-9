# Host engine v1 — frozen evaluation rule and technique manifest

Frozen 24 November 2026, **before any measurement**: no native or Sigma rule has been run on
any EVTX-ATTACK-SAMPLES file or on the owner's logs.

| File | What it is |
| --- | --- |
| `selection_rule.md` | §4 of `docs/design/host-engine-v1.md` (with amendment 2, §4.7, and amendment 3, §4.8) copied unchanged |
| `technique_manifest.json` | Expected ATT&CK v20.0 techniques per sample, from sample paths only |
| `FREEZE.json` | SHA-256 of both files and of the pinned inputs (Sigma lock, samples lock, ATT&CK catalogue, manifest builder) |

Amendment 3 (24 November 2026, still before any measurement): the owner labels owner-PC
alerts per rule (one label per rule, optional split by alert number) after seeing a local
summary and up to 10 examples; gate counting is unchanged. `FREEZE.json` records the
previous rule hash `deece958…49ab` and the new one.

## Technique manifest

- Source: EVTX-ATTACK-SAMPLES commit `4ceed2f4706daf601c212a8f91c113dd85349a2c` (GPL-3.0; files
  stay local under ignored `data/external/`).
- Labels come only from each sample's folder and file name, through the fixed keyword table in
  `evaluation/host_technique_manifest.py`, plus ATT&CK ids written in names. Revoked ids are
  resolved in the pinned v20.0 catalogue (`T1178` → `T1134.005`, `T1186` → `T1055.013`).
  No sample was opened; the repository's event-level `evtx_data.csv` was not used; its
  per-technique mapping is reachable only through a URL shortener and was not used.
- 278 paths, 277 distinct samples (one file appears at two paths). 243 labelled, 34
  excluded as undetermined. Split by the last hex digit of the content SHA-256: 136
  development, 141 report (120 and 123 labelled).
- Labels are coarse: a name says what the lab exercised, not that every event in the file
  is malicious, and some techniques may be present without being named.

Reproduce: `python evaluation/host_technique_manifest.py` (needs the pinned ATT&CK catalogue).
`backend/tests/test_host_manifest.py` checks reproducibility and the frozen hashes.

## Not yet done (each needs the owner)

1. Benign corpus: the owner's own PC logs (design §4.4) — only aggregate counts will be
   committed, reported as "one owner PC, one user's habits".
2. Development-half measurement and selection, then the shipped-rule manifest.
3. Report-half measurement, once, as exposed development evidence.

## Dated notes

2026-11-25 — Benign measurement window fixed before any results were seen. The current export covers fewer than 7 full host-days. To reach N >= 7, the owner raised the log size caps on 2026-11-25 and will re-export after 2026-11-28T00:00Z. The measurement runs once on that export. Host-days are counted by host_days() in evaluation/host_benign_measure.py (design §4.4) as-is, with no padding, and the window will not be changed after results are seen.
