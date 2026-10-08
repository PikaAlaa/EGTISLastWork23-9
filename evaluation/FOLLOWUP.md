# Reviewer follow-up evidence

The updated evidence ZIP supplied on 8 October 2026 contains five files under
`review-evidence/followup-2026-10-08/`: the original Linux HTTP scripts, README and
captured JSON results. They are preserved byte-for-byte. `IMPORT-PROVENANCE.json`
records their SHA-256 checksums and the source archive checksum. The original
`review-evidence/cases.py` matches the newly supplied archive exactly.

The original scripts hard-code a Linux import path and localhost port 8010 and read
that machine's `.env`. Their README describes a **test-only** snapshot timestamp
change. They are historical reviewer evidence; do not apply that change to the live
database. The portable runner below does not run those scripts or alter feed dates.

## Repeat locally

From the project root after installation:

```powershell
.\.venv\Scripts\python.exe evaluation/run_followup.py
.\.venv\Scripts\python.exe -m pytest -q
```

On Linux use the installed environment's `python` in place of the Windows path.

The runner loads the real selected model and uses an isolated in-memory SQLite
fixture with one known phishing URL. Frozen fixture health is explicit and restored
after the run. It invokes the scanner in process; this is **not** another HTTP/API
transport test. Authentication and HTTP behavior remain covered by endpoint tests
and the separate local smoke checks. No external network request, live database
change, model training or final-test access occurs.

The 15 extra inputs in `followup-probes.json` are transcribed from the preserved
`probe.py` table, including its eleven-link generated message. They are now exposed
development regressions and must not be claimed as unseen or used as final accuracy
evidence. They were not added to training data.

## Recorded local results

- Original detection inputs: 23/23 meet their expected outcomes.
- Robustness inputs: 7/7 meet their expected outcomes.
- Additional probes: 14/15 meet their expected outcomes.
- All 15 additional verdicts match the reviewer's supplied captured results.
- The NBE notice is still HIGH where the expectation is LOW/MEDIUM. This is a real,
  unresolved false alarm, not a passing case.
- The twelve invented everyday SMS still give 5 HIGH, 3 MEDIUM and 4 LOW.
- The complete suite reports 144 passed and one expected failure. The expected
  failure is strict: if the NBE case improves, review and update that regression.

The portable runner exits nonzero for unexpected failures. Its zero exit status
allows the explicitly recorded known limitation; read the result counts, not only
the process status. Detailed local results are saved in
`local-results/followup-replay.json`. The original captured reviewer results remain
separate and unchanged.

These files contain phishing URLs as inert test data. Do not open them in a browser.
Source descriptions such as "genuine NBE notice" are reviewer-provided assertions;
this small probe is not a substitute for consented, independently labelled real-SMS
evaluation. Representative data, approved targets and final protocols remain pending.
