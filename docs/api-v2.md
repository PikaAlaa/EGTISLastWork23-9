# Analyze API — decision-v2

`POST /analyze`, protected by server-side `X-API-Key` when configured. The browser uses
same-origin `/api/analyze` through the Node proxy and receives no key. Send JSON:

```json
{"url":"https://example.com/","text":"Optional suspicious message","sender_type":"unknown"}
```

At least one nonempty string is required. Text max 5,000 characters; URL max 2,048;
unknown fields, invalid hosts, schemes and ports return 400. HTTP(S), bare domains,
IDNA, userinfo and scheme-specific default ports use the shared parser. Fragments do
not change reputation identity; path/query case and content remain evidence. An
additional tracking-stripped lookup key never rewrites the analyzed URL.

`sender_type` is optional: `company_name`, `short_code`, `mobile_number` or `unknown`.
Omitting it or sending `null` means unknown. It describes what the user sees in the
SMS sender display; do not submit the actual number or sender name. Invalid enum
values/types return 400. The browser sends this field only with message text.

A bank, wallet, payment/finance or telecom sender claim together with
`sender_type=mobile_number` adds `brand_claim_from_mobile_number`. Named claims
use the eligible brand registry and curated Arabic/English keyword lists; branded
prefixes, sender signatures and explicit generic bank/wallet/telecom claims are
recognized. Casual mid-sentence brand mentions alone are insufficient. This is a
heuristic, not verified sender identity or an exhaustive claim parser.

This signal alone produces MEDIUM. It does not corroborate a high text-model score
into HIGH. Other independent decisive findings keep their normal precedence; missing
required checks still produce INCOMPLETE. Advice explains that banks normally send
under their company name, but sender names can be faked. A company-name/short-code
selection never reduces existing evidence or proves legitimacy.

The sender field is transient: no database column, input echo, browser storage or
logging is added. Existing minimal scan metadata can retain the computed reason code,
as it retains other supporting signals; the submitted sender category itself is not
stored. The existing privacy/retention policy is otherwise unchanged.

The response includes:

| Field | Meaning |
| --- | --- |
| verdict | LOW, MEDIUM, HIGH, INCOMPLETE |
| decisive_reason | Stable reason/rule code, translated by the client |
| supporting_signals | All applicable supporting/decisive reason codes |
| checked_links | Up to 10 destinations, real hosts, brand/pattern/blacklist findings |
| links_truncated | Additional destinations were present; analysis is incomplete |
| text_finding | Model output, model/artifact version and window count; nullable |
| analysis_complete | Whether every required applicable check completed |
| checks_unavailable | Stable failure codes without private snippets |
| final_score | Heuristic indicator strength; not calibrated confidence |
| policy_version | decision-v2 |
| timing_ms | Processing time |
| saved, save_error | Persistence outcome independent of the verdict |

The decision order is decisive HIGH, otherwise INCOMPLETE, otherwise supporting MEDIUM,
otherwise LOW. All applicable checks run before deciding. Official domains bypass only
brand resemblance; they never override text or exact-blacklist evidence. No arithmetic
fusion, confidence percentage or unvalidated two-signal escalation is used.

Brand findings can include `official_contact`: a manually verified organization-owned
contact page, Egyptian retail hotline and verification date. Details are from the
registry, never from submitted content. Four banks currently have sourced hotlines;
other brands fall back to advice to use an independently trusted app/contact channel.
Sources and dates are in `backend/app/core/brand_contacts.py`.

Raw message text is not echoed. Checked URLs are returned for the immediate analysis,
including path/query evidence, but are never persisted as scan submissions. Scan records
contain hashes, verdicts, reason codes and versions only. Model output probabilities
describe classifier output, not a validated probability that the user's message is fraud.

Database/model failures cannot silently become LOW. Missing authentication is 401,
throttling 429, unexpected unavailable service 503. Saving failure is a normal 200
verdict with `saved=false`. Health has separate live and component-aware ready routes.
