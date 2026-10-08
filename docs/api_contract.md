# Shared API contract — decision-v2

The authoritative scan request, response, evidence ordering, privacy and failure
contract is [api-v2.md](api-v2.md). This supersedes the three-verdict weighted-fusion
contract retained in `history/destination-11e95da-api_contract.md`.

`POST /analyze` accepts `text` and/or `url` and returns HIGH, INCOMPLETE, MEDIUM or LOW
with reason codes and complete-check metadata. Saving failure preserves the verdict
with `saved=false`. API keys stay on the server; browser requests use the same-origin
proxy at `/api`. No confidence percentage or raw-message storage is permitted.

## Threats and statistics

- `GET /threats`: optional `source`, `is_active`, `limit` (1–500, default 50),
  `offset` (>=0, default 0). Returns `total_matching,limit,offset,results`.
  Each entry contains domain, source, brand target, reputation, active flag and dates;
  raw phishing URL paths and hashes are not exposed in the browsing endpoint.
- `GET /stats`: returns `blacklist` (`total_entries,active_entries,by_source`) and
  `scans` (`total_scans,by_verdict,average_final_score`). Verdict counts include
  INCOMPLETE; an empty database returns zero counts and a null average.
- Both routes use the same server API-key requirement as `/analyze` when configured.
- `GET /health/live` reports liveness. `GET /health/ready` reports components and
  returns 200 ready/degraded if at least one scanner can work, 503 if neither can.

The deployed `/openapi.json` describes current schemas. The frontend types and
`backend/tests/test_endpoints.py` are checked against this revision.
