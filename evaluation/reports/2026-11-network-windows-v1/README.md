# network.windows v1 — sample sources and expected-detection manifest

Written 27 November 2026 (design `docs/design/network-windows-v1.md` §9 steps 6 and 7), **before
any measurement**: no network.windows rule has been run on any sample or on the owner's logs.
Frozen the same day (step 7) together with `expected_detections.json`.

| File | What it is |
| --- | --- |
| `selection_rule.md` | §4 of the design, with the §4.11 pre-measurement clarifications of 27 November 2026, copied unchanged |
| `expected_detections.json` | Per rule: gate techniques, expected development- and report-half samples, and the gate 2 obligation |
| `FREEZE.json` | SHA-256 of both files and of the pinned inputs (blocklist lock, samples lock, host technique manifest, builder, readers, detections, blocklist loader, engine, requirements), the popular-list and ATT&CK hashes, the URL model pin |

Frozen facts (§4.11): the only list candidate is Feodo Tracker (lock raw SHA-256
`692d3197…260b6c`; SSL Blacklist deprecated 2025-01-03). Gate techniques: N5 `T1568.002`, N7
`T1571`, N8 `T1071.004`, exact match only. No rule has an expected sample, so every shipped
rule ships `unvalidated_on_samples` with confidence capped at `single_signal`. Later changes
are dated pre-result amendments citing the `selection_rule.md` SHA-256
(`backend/tests/test_network_windows_freeze.py` checks the hashes and that the rule equals §4).

## Method (as the host engine, unchanged)

- Per-file techniques come from the host engine's frozen, path-only technique manifest
  (`../2026-11-host-v1/technique_manifest.json`; SHA-256 checked against its `FREEZE.json`).
  No new labels were written, and no sample was opened to label it.
- Gate techniques are those design §5 maps to a rule: N5 `T1568.002`, N7 `T1571`, N8
  `T1071.004`. Matching is exact (host-engine-v1 §4.7 item 3). N1–N4, N6 and N9 have no §5
  technique. Rule-text exclusions: N1 unit tests only (§3.2), N2 inactive (§10 decision 1),
  N9 emits nothing on samples (§4.3).
- Builder: `evaluation/network_expected_detections.py`; test:
  `backend/tests/test_network_expected_detections.py` (reproducibility and the rules above).

## Result

**No rule has an expected sample** in either half. No sample label carries `T1568.002`,
`T1571` or `T1071.004`. Nine samples carry network-related techniques that §5 lists as not
mapped (`T1572` RDP tunnelling, `T1090.001` port forwarding, `T1105` transfer); they are
listed in the manifest for transparency and create no obligation. By gate 2, every rule
that ships passes only through its invented positive and negative tests and ships
`unvalidated_on_samples`, with confidence capped at `single_signal`. This is a stated
limitation of v1, not a result to tune.

## Sources (design §11 S1–S3)

| | Source | Status |
| --- | --- | --- |
| S1 | EVTX-ATTACK-SAMPLES, commit `4ceed2f4706d…` (GPL-3.0) | Used through path labels. The local copy was checked read-only on 27 November 2026: all 280 pinned files match the lock's size and SHA-256 (bytes hashed only; no event parsed; read from the main checkout's ignored folder, nothing written there). |
| S2 | UMUDGA (Mendeley Data, licence shown: MIT) | **Not used: contains executables** (DGA executables in the bundle). Not downloaded (owner decision, 27 November 2026). N5 has no labelled DGA sample. |
| S3 | DNS-tunnelling sample in Windows log form | None found (public sets are PCAP/CSV). N8 has no sample. |

The samples stay local under ignored `data/external/`; nothing from them is committed except
paths and hashes already in `data/evtx-attack-samples-lock.json`.
