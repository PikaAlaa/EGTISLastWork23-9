# Local browser extension v1 — design

Status: **design only**, 26 November 2026. Chrome/Edge Manifest V3 is the proposed
target; all browser API, permission, platform and distribution details are
**to verify** against the official documentation in §10. Nothing is implemented,
installed, published, downloaded or measured here.

## 0. Constraints

Apply `CLAUDE.md`, `README.md`, [core v1](core-v1.md),
[engine authors](../engine-authors.md) and [host design](host-engine-v1.md).
Only the explicitly selected current URL may be sent to local ETIS on literal
`127.0.0.1`; no cloud, remote reputation service, DNS/WHOIS or online lookups.
Never fetch/resolve any observed URL, including during a demo. No messages,
URLs, hashes or headers go to any external service. Never send page content.
All generated example URLs/pages are **invented**.

This batch adds this document only: no existing file, code, test, dependency,
`evaluation/`, targets, frozen rules/splits, `data/`, model or threshold changes.
No secrets, installation, push, merge or history rewrite. The extension adds no
detector or model: it displays the existing frozen URL policy's result. Any
future new detection still requires a separate rule and Finding through core
`record_findings`, without modifying the deployed verdict path.

**No browsing history includes hash history.** Neither extension nor server may
persist visited URLs, URL hashes, check timestamps tied to tabs, Findings,
incidents, scan records, caches or request logs for these checks. Therefore this
design needs a new stateless local endpoint, not the existing saving `/analyze`
endpoint. A local database of visited hashes would violate the requirement.

## 1. Scope and inputs

V1 is **user initiated**: click the extension action to check the current
top-level tab. It does not subscribe to background navigation, scan other tabs,
follow links or maintain a list of checked pages. This scope permits a small
permission set; automatic navigation scanning would need a separate design.

The background component reads the current tab's HTTP(S) URL through a browser
API, not from page DOM or a page-supplied message. Refuse embedded credentials,
non-HTTP(S) schemes, browser-internal pages, file/data/blob URLs and unsupported
contexts. Never decode data URLs or inspect their payloads. Incognito is disabled
in v1, subject to verified platform behavior. No screenshots, page title,
referrer, cookies, forms, selected text, HTML, document text or browsing history
are collected. No observer script watches subsequent page changes.

Transmit the selected URL including query to loopback in a POST body, after
removing its fragment locally. Query values can be sensitive; the pairing UI
states that the URL is read only for this local check and never retained.
Fragments are excluded from this extension's check; no fragment-sensitive claim
is made. Existing model preprocessing and thresholds remain unchanged. The
request URL itself is a fixed local endpoint, never a page-derived target.

## 2. Detection and interaction logic

1. User invokes the action. With no pairing, show the local pairing instructions
   and make no check request. With pairing, capture top-level tab/document
   identity and URL in memory; validate input and remove fragment.
2. The background component sends one authenticated request to the exact
   allowlisted origin/path in §2.2. Disable redirects and ambient cookies; never
   fall back to another host, hostname, port, proxy, cloud endpoint or scheme.
   Browser/system transport behavior is **to verify** with an egress test.
3. The local stateless adapter runs the existing URL-only decision policy with
   the same models, thresholds, offline feed snapshot and preprocessing, without
   scan/Finding persistence. It does not call its own HTTP `/analyze` endpoint,
   invoke feed refresh or contact the destination. Model/component failure is
   visible as incomplete/unavailable, not a safe result.
4. Validate response schema, request nonce and result enums. Before injection,
   verify the active tab/document and captured URL are still the same. If the
   document navigated, the user closed/switched the tab, or the request expired,
   discard the response and remove the pending in-memory state. No automatic
   recheck of the new page.
5. For warning outcomes, inject a locally bundled banner with fixed localized
   text, reason-code labels and a close control. The injection only creates its
   own UI; it does not read page text/attributes/forms, add external resources,
   send messages containing page content or expose the pairing token.
6. Clear request/response/tab state after rendering or failure. The popup retains
   only the currently displayed result while open, then forgets it. Closing a
   banner does not create a per-site dismissal list or permanent exception.

The page can modify/spoof a DOM banner. Treat the extension popup/action UI as
the trusted place to inspect a result; never claim the banner cannot be removed.
Banner insertion/Shadow DOM, navigation identity and restricted-page support
are **to verify** before implementation. A failed injection still shows the
result in the extension popup and a `banner_unavailable` coverage state.

### 2.1 Permissions, individually justified (proposed, to verify)

| Permission or feature | Purpose / boundary |
| --- | --- |
| `activeTab` | Temporary access to the user-invoked current tab URL and banner target. Verify lifetime and navigation behavior; no background tab enumeration. |
| `scripting` | Inject only the bundled banner into that permitted top-level document. No general DOM scraping or persistent content scripts. |
| `storage` | Store pairing token, paired server identity, extension instance ID and language locally only. No URL/result/site lists; never use sync storage. Verify access can be limited to trusted extension contexts. |
| Host access proposed as `http://127.0.0.1/*` | Background request to local ETIS. Match-pattern port granularity is to verify; runtime allowlist must enforce exactly port `8000` and the §2.2 paths even if manifest access spans more ports. |
| Extension action/popup | Explicit user invocation and trusted result display; verify which declarations require a permission. |

Do not request `history`, broad `tabs`, `webRequest`, cookies, notifications,
clipboard, downloads, native messaging, `<all_urls>` or general website host
access. Do not expose `externally_connectable` or a page-callable analysis bridge.
Whether the proposed set suffices in each browser is **to verify**; unsupported
behavior blocks that feature rather than silently widening permissions.

### 2.2 Proposed local API contract

These routes are **new proposals**, not existing repository behavior. The fixed
backend origin is `http://127.0.0.1:8000`, consistent with the repository's local
upstream default in `etis-frontend/server.mjs`. No DNS hostname is used. A future
port change requires an explicit reviewed configuration/version change; no port
discovery or fallback scan. Do not give the extension the existing general API key.

| Contract | Proposed shape / behavior |
| --- | --- |
| Pair exchange | `POST /extension/v1/pair`, JSON with protocol version, locally copied one-use pairing secret and random extension-instance ID. Exact extension origin is checked against the operator-approved origin. Returns a narrowly scoped extension token and local server-instance identity. |
| Check | `POST /extension/v1/check`, JSON `{schema_version: "extension-check-v1", url: <current inert URL without fragment>, request_ref: <random nonce>}`. Dedicated bearer token in request header. No submitted custom headers, messages, title, user identity or tab ID. |
| Success | JSON echoes schema version and nonce, includes server-instance identity, existing `LOW|MEDIUM|HIGH|INCOMPLETE` verdict, allowlisted reason codes, policy/model versions and unavailable-component flags. It never echoes the URL, its hash or free-form model text. |
| Errors | Fixed codes such as `pairing_required`, `pairing_invalid`, `input_invalid`, `limit_exceeded`, `service_unavailable`, `protocol_mismatch`. Unknown fields rejected; no input excerpts. Use verified HTTP status conventions before implementation. |
| Transport | JSON only; responses `Cache-Control: no-store`; no cookies, redirect following, URL query parameters, GET analysis route or public-network listener. Timeout, body/URL limits and rate/concurrency budgets must be frozen before any measurement. |

The extension uses the returned verdict unchanged: HIGH/MEDIUM show a warning,
INCOMPLETE says the check is incomplete and lists unavailable check categories,
LOW says no warning was found by this local check without promising safety.
No severity score is synthesized or threshold changed. If all analysis components
are unavailable, show unavailable regardless of any transport success.

### 2.3 Pairing and local transport boundary

The user starts ETIS and opens its existing trusted local UI themselves. A
future local pairing panel shows the extension's declared ID/origin and a
one-use random secret. The operator approves that exact installed extension
origin and copies the secret into the extension popup. Do not read the clipboard
programmatically or put secrets in links, command lines, logs or Git.

The server exchanges the one-use secret for a random revocable token scoped
only to extension checks and that extension instance/origin. Secret lifetime,
entropy, attempt/rate limits and token storage format are pre-implementation
security parameters to freeze (§10), not numbers invented as measured safety.
The server stores a verifier/digest and revocation metadata; extension uses
local-only protected storage. Rotate/revoke in the local ETIS UI; revocation,
reinstall, lost token or server-instance mismatch requires pairing again.

No unauthenticated endpoint mints tokens, and a webpage cannot use pair/check
via a tokenless or cookie-based bypass. Validate literal Host (including port),
exact allowed extension Origin and bearer scope; no wildcard CORS, reflection,
`null`-origin exemption or “extension scheme means trusted” rule. Browser Origin
presence, extension ID behavior and local/private-network restrictions are
**to verify**. If exact origin enforcement cannot be established for a browser,
do not enable its endpoint until a reviewed binding replaces it.

Plain local HTTP is the proposed transport; this does not authenticate a server
against a malicious local process or encrypt memory. Token/server identity
binding narrows accidental cross-service use but is not proof against local
malware impersonating ETIS. Do not claim that browser storage protects tokens
from a compromised OS. Alternative local transport is an open question, not a
hidden cloud fallback. Threat-model/security claims are **to verify** (§10).

### 2.4 ETIS stopped or unreachable

Connection refusal, timeout, blocked loopback, invalid/revoked token, incompatible
protocol or model failure produces “ETIS unavailable — this page was not fully
checked” in the extension UI. It is never cached as LOW. No retry queue or
history is kept. Offer a user-triggered retry after they start/pair ETIS; no
automatic launch, background polling or network fallback. Existing browser
navigation continues; this v1 warns and does not implement a network blocker.

## 3. Data and sources

No browsing corpus, private history or external threat service. The runtime uses
only the existing locally installed models/feed snapshot/rules, read without
updating. Browser behavior is verified later against official Chrome/Edge docs.
Demonstration pages and requested URL strings must be invented and synthetic;
use a local harness that supplies URL strings without navigating to them.
No real malicious page is needed to demonstrate a warning.

## 4. Evaluation rule — before measurement

Initial pre-result protocol: **26 November 2026**, no results. Before execution,
freeze this rule SHA-256, exact manifest/permissions, browser versions, pairing
parameters, resource budgets, endpoint protocol, unchanged policy/model IDs,
invented fixture-label/family lists and demo script. No `evaluation/` changes
in this batch. Use separately authorized isolated test/report locations later.

Data: invented URL/response fixtures covering every verdict and failure state,
navigation races, forged page requests, hostile header/body input, forged local
service responses, pairing/revocation, missing server and blocked loopback.
Freeze exposed development/report families before running; same-template
variants remain together. Stubs test banner/state behavior; separate local
policy parity fixtures exercise real scoring without fabricated expected scores.

Gates: every expected UI/protocol state must pass; zero requests beyond exact
loopback allowlist; zero reads/submissions of page content; zero persisted URLs,
hashes, results or tab-linked check times across extension/server/log surfaces;
zero authentication bypasses; zero stale-result banners on a different document;
zero existing verdict differences between stateless and existing pure scoring
for the same supplied URL. Zero synthetic warning banners on LOW controls;
incomplete/offline controls must never display safe/LOW. All limits are enforced.

Freeze the candidate before one report-family pass. Any gate failure blocks v1;
no permission widening, selective removal or gate relaxation based on report
results. Report per-state correctness/error counts and denominators, injected
banner versus popup-only coverage, pair/auth failure counts, actual latency and
resource observations with machine/browser versions, and all excluded contexts.
No fabricated latency target or population accuracy claim. Report fixtures are
exposed; fixes need a new version and fresh report families.

No sealed final test or live phishing navigation. Amendments are dated
pre-result records citing previous hashes, rationale and affected fresh fixture
manifest; disclose any prior exposure. No browsing accuracy is inferred from
invented URL strings or stubbed verdicts.

## 5. ATT&CK

The extension adds no independent adversary observation: current URL plus a
warning is insufficient to infer phishing delivery, user execution or compromise.
**No extension ATT&CK mapping is emitted.** Core `record_findings` is not invoked
by transient checks (§6), so no verdict-only technique mapping or coverage count
is created. If future explicit evidence capture is designed, check candidate IDs
against local v20.0 catalogues, with the read-only fallback and hashes in
[provider registry §5](provider-registry-v1.md), or mark them **to verify**.
No uncatalogued technique IDs are proposed here.

## 6. Findings, severity, confidence and correlation

This feature is a stateless client/adapter to an existing detector, not a new
engine. It adds **no Finding kinds** and does not invoke `record_findings`, scan
saving, indicator upserts, dedup records, incident correlation or ATT&CK mapping.
That is essential to the no-history requirement; rolling back a transaction
after recording is insufficient because logs or other side effects may survive.

| Existing response | Temporary UI state (not Finding severity) |
| --- | --- |
| HIGH | High warning banner plus popup result |
| MEDIUM | Caution banner plus popup result |
| INCOMPLETE | Incomplete-check notice, with unavailable categories |
| LOW | Popup result only, no warning and no safety guarantee |
| No valid response | Unavailable/unpaired UI, never a verdict |

| Confidence handling | Rule |
| --- | --- |
| New confidence value | None; do not calculate a percentage or categorical confidence from the browser URL. |
| Existing model strength | Do not reinterpret as authentication, confirmed danger or calibrated risk. |
| Missing component or response | Explicit unavailable coverage; no invented confidence. |

No indicators or evidence are persisted, even hashes. Rule codes/model versions
are held only for the open result display; no scan IDs, historical findings or
incident links are returned. No automatic incident correlation occurs.
If the user later wants to save evidence, that needs a separate explicit-import
design, retention controls and separate Findings through `record_findings`;
this version has no “save visited page” function. Designs 1–3's rules are not
silently run without their required claim/message/header inputs.

## 7. Privacy

| Survives a check/restart | Never retained |
| --- | --- |
| Local pairing token, server identity, approved extension origin/instance, language and revocation metadata | URL, URL hash, query/fragment, tab ID/document ID, page title/content, check time, result, per-site dismissals |
| Bundled static UI/rule-code translations | Scan/Finding/incident rows, metrics labelled by URL/hash/tab, request/response caches, crash/debug payloads |

Use no sync storage, telemetry, remote scripts/fonts or remote configuration.
Keep token out of content-script messages, DOM, page globals and diagnostics.
The server must suppress access/body/auth/error logs and tracing for these
routes, including middleware/proxy layers. “No plaintext URL logging” alone is
insufficient if hashes or structured traces survive. Clear memory on completion,
cancellation, timeout and worker termination. No retention job substitutes for
never storing browser data. The existing application's explicit scan history
behavior is outside this adapter; never route a browser check through it.

## 8. Test and demonstration plan

Use a local mocked browser/service harness and invented pages. Place secret
marker strings in HTML, title, fields and selection; they must never be read
for analysis, transmitted, logged or stored. Check only the API-supplied current
URL. Verify non-HTTP/data URLs are rejected without payload decoding, response
schema/nonce validation, tab/document race cancellation, banner spoof limitations,
restricted pages, no persistent state after browser/server restart, token
isolation/rotation/revocation, Host/Origin/auth failures and denied redirects.
Inspect extension storage, server DB, logs/caches/traces and outbound sockets.

Demo sequence, with every fixture/page/URL labelled **invented**:

1. Start local ETIS, pair explicitly and show the exact minimal permissions.
2. Open a locally served invented demo page. A harness supplies the invented
   string `https://example.com/invented-check` as a check input; do not navigate
   to or resolve that external-looking string. A clearly labelled stubbed HIGH
   response demonstrates banner rendering, without claiming a model detection.
3. Show LOW and INCOMPLETE invented response fixtures, stale-navigation
   cancellation and popup-only behavior where banner injection is denied.
4. Stop ETIS, retry explicitly and show unavailable; revoke pairing and show
   re-pairing. Restart and verify there is no history in storage or database.
5. Separately exercise the real stateless policy with inert invented URL strings
   in the local harness, report actual output without promising a HIGH result.
   Never visit a phishing destination to produce a warning.

Future implementation uses isolated databases and existing parity, pytest,
database initialization, frontend build and lint, plus extension-specific browser
checks after the toolchain is verified. No installation or tests in this batch;
no sealed final test ever runs as part of this protocol.

## 9. Implementation steps (small commits)

1. Verify APIs/permissions/transport and freeze resource/pairing parameters.
2. Add stateless local scoring adapter and protocol, with no persistence/log path.
3. Add local pairing/revocation and exact Host/Origin/token scope checks.
4. Add action/popup and local-only settings; no page-content bridge.
5. Add bundled banner and document/navigation race guards.
6. Add unavailable/incomplete states, privacy/egress tests and bilingual UI.
7. Freeze §4 manifests, run exposed checks and the labelled local demo, and
   document browser limitations. Apply project checks at each relevant commit.
8. Distribution/signing is separate future work after official policy verification;
   this design authorizes no browser-store publishing or external uploads.

### Open questions

- Does the proposed minimal permission set support exact document targeting and loopback requests in both browsers?
- How will the operator verify installed extension IDs/origins during local pairing, especially for development builds?
- Which verified token entropy/lifetime/rate/resource limits suit the local threat model and project PC?
- Can all middleware, tracing and browser debugging surfaces guarantee no retained URL or hash history?
- Is user-initiated checking sufficient for v1? Automatic navigation checking requires a separate permission/privacy design.
- Is a different local transport needed to strengthen server authentication against local process impersonation?

## 10. To verify

- **To verify:** Chrome/Edge Manifest V3 capabilities, worker lifetime, permission
  warnings, activeTab scope, scripting/document targeting, storage access,
  restricted pages/incognito, host-pattern port behavior and stable extension IDs;
  read official Chrome Extensions and Microsoft Edge Extensions documentation.
- **To verify:** extension fetch Origin/CORS behavior, cookies/redirect controls,
  browser loopback/private-network restrictions and OS proxy handling; read
  official browser platform/fetch security documentation and test local egress.
- **To verify:** pairing secret/token generation, local storage guarantees,
  revocation and local-server impersonation threat assumptions; read selected
  browser/OS and cryptographic-library security documentation and review the
  current ETIS local authentication design. No unreviewed numeric security claim.
- **To verify:** complete request logging/tracing/cache suppression and stateless
  policy-adapter side effects; inspect all local middleware/proxy/model paths
  before implementation. Existing `/analyze` must remain unchanged.
- **To verify:** extension distribution/signing/store and privacy disclosure
  requirements and applicable local law; read official browser store policies
  and official legislation before distribution. No compliance claim here.

## Sources

Read locally: `CLAUDE.md`, `README.md`, `docs/design/core-v1.md`,
`docs/engine-authors.md`, `docs/design/host-engine-v1.md`, `docs/api-v2.md`,
`backend/app/engines/registry.py`, `backend/app/services/findings.py`,
`backend/app/main.py`, `etis-frontend/server.mjs` and the new designs 1–3.
The local origin/port proposal is grounded in `etis-frontend/server.mjs`;
extension endpoints and pairing are proposals, not existing APIs.

Unopened official reading sources, all **to verify**, not example destinations:
[Chrome Extensions documentation](https://developer.chrome.com/docs/extensions/),
[Chrome permissions](https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions),
[Chrome cross-origin requests](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests),
[Microsoft Edge extensions](https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/),
[Fetch Standard](https://fetch.spec.whatwg.org/).
