# API contract

## `POST /analyze`

Request:

```json
{"text": "optional message", "url": "https://optional.example"}
```

At least one field is required. Response fields:

- `final_score`: number from 0 to 100.
- `verdict`: `LOW`, `MEDIUM`, or `HIGH`.
- `reason`: plain-language summary.
- `engines_applied`: names of engines that produced a score.
- `weighted_contributions`: point contribution by engine.
- `engine_details`: explainability payload from every engine, including non-applicable engines.
- `saved`: whether persistence succeeded.
- `save_error`: redacted persistence error or `null`.

Scoring must still be returned if persistence fails.

## `GET /threats`

Query parameters: `page >= 1`, `page_size` from 1 to 100, optional `source` and `domain` filters.

Returns `{items, page, page_size, total}`.

## `GET /stats`

Returns blacklist counts, scan counts, verdict counts, and model availability. Empty databases return zeros rather than errors.
