# Follow-up checks on the 8 Oct 2026 local build ("review-fixed" zip)

Run against the updated backend on Linux, Python 3.12, the zip's own `requirements-runtime.txt`,
SQLite initialised with `scripts/initialize.py --seed-archive`.

**Test-only change:** the archive blacklist dates from July, so the build correctly reports it as
stale. To test detection logic offline, `feed_snapshots.captured_at` was set to the current time in
the test database copy. A live feed refresh does this properly.

- `run_upd.py <repo> <out.json>`: the review's 23 API cases, 12 invented everyday SMS and
  7 robustness probes from `../cases.py`, sent with the local API key from the repo's `.env`.
- `probe.py <repo> <out.json>`: 15 new cases the build had never seen (lookalikes, Cyrillic letters,
  disguised links in SMS, official subdomains, bare domains, port handling, the 10-link limit).

Results (8 Oct 2026): 23/23 cases and 7/7 robustness probes pass; everyday SMS 5 HIGH,
3 MEDIUM, 4 LOW; 14/15 new probes as expected. The miss is a genuine NBE notice with the
official website, scored HIGH by the text model (`text_high`).

These files contain live phishing URLs as test data; don't open them in a browser.
