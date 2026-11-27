# Windows user-space agent and LAN server v1 (FR-11) — design

Status: **design only** (27 November 2026), branch `feat/agent-design-v1.1`, updated with
the [core v2](core-v2.md) §3.6 alignment changes and the owner's review decisions of
27 November 2026 (§11). No code, migration, dependency, certificate, network listener,
measurement or system change accompanies this document. A fact is marked **verified** only
when it comes directly from this repository's existing code or from a source already read
and recorded in [network-windows-v1](network-windows-v1.md) or
[malware-engine-v1](malware-engine-v1.md); every other fact about Windows permissions,
TLS/certificate pinning in Python, local credential storage, LAN transport and Egyptian Law
No. 151 of 2020 (PDPL) is marked **to verify**, with the primary source to read, and is
listed again in §12. No number in this document comes from a measurement, and no legal
compliance claim is made.

This design covers **FR-11**: a non-administrative Windows agent that runs the existing
local host (`host.windows`), malware (`malware.files`) and Windows network-lite
(`network.windows`) engines on an employee's Windows PC, pseudonymises local identifiers on
the endpoint using `ETIS_HOST_PSEUDONYM_KEY` (and `ETIS_MALWARE_PSEUDONYM_KEY` for file path
references), and forwards **only `finding-v1` Findings** (plus non-content batch coverage
and health counts) over pinned-certificate HTTPS to an ETIS server on the company LAN. The
LAN server re-wraps endpoint device and account pseudonyms (`hmac:<32 hex>`) with a
server-only key (`ETIS_SERVER_REF_KEY`) into stored references (`srv:<32 hex>`) before any
storage ([core v2](core-v2.md) §3.2, §3.6). Raw event logs, firewall logs, connection
tables, file contents, user names, computer names, command lines and file paths never leave
the PC.

---

## 0. Constraints and v1 scope

| Constraint | How this design keeps it |
| --- | --- |
| **No administrator rights** | The agent runs strictly as the signed-in standard Windows user. It never requests UAC elevation (`requireAdministrator`), installs a driver, changes audit or firewall policy, or reads channels locked to administrators (§1.2). Sources that cannot be read without administrator rights are reported as `not_visible` in the coverage report, never as clean. |
| **No silent persistence** | No Windows Service, no `HKLM` registry writes, and no scheduled task or `HKCU` startup entry unless the user explicitly opts in via a separate user-space flag and can remove it at any time without administrator rights (§4.4). |
| **Findings only on the wire** | Only validated `finding-v1` payloads (`app.core.findings.Finding`, `extra='forbid'`) and non-content batch coverage/health counts cross the LAN. Raw `.evtx` files, `pfirewall.log`, snapshots, scanned binaries, strings, non-alerting DNS/connection records, user names, host names, command lines and paths are rejected at the schema boundary and never transmitted (§2, §5.2). |
| **Two-stage pseudonymisation (endpoint `hmac:` → server `srv:`)** | On the endpoint, `host_ref` / `device_ref` and `account_ref` are computed locally with `app.engines.host.pseudonyms.Pseudonymizer` (`ETIS_HOST_PSEUDONYM_KEY`, **verified** in `backend/app/engines/host/pseudonyms.py`) and the shared helpers in `app/core/device_names.py` ([core v2](core-v2.md) §3.2); `path_ref` uses `ETIS_MALWARE_PSEUDONYM_KEY` (**verified** in `scripts/initialize.py`). On the server, `ETIS_SERVER_REF_KEY` (never sent to any agent) re-wraps `hmac:` device and account refs into `srv:<32 hex>` before any storage (§1.3, §5.2). The server never receives raw computer names, account names, user SIDs or paths, and never stores `hmac:` device or account refs. |
| **LAN HTTPS with pinned server certificate** | The agent connects only to a literal RFC 1918 / IPv6 ULA LAN address (or operator-pinned LAN hostname resolved within the declared `--local-net`) over HTTPS, verifying the server leaf certificate's DER SHA-256 fingerprint against the `primary` (or optional `next`) pin recorded at pairing (§4.2). No cloud relay, public internet listener, redirect following or proxy fallback. |
| **Bounded offline queue** | When the LAN server is unreachable, already-sanitised `finding-v1` batches wait in a user-only local queue capped by byte size and batch/Finding count, with explicit overflow accounting (§4.3). Raw logs are never queued. |
| **Written employee notice (PDPL 151/2020)** | Pairing displays a bilingual (Arabic/English) written notice explaining local processing, what leaves the PC, what never leaves, retention and uninstall, and records the acknowledged notice version before any token is used (§7.4). Statutory details are **to verify** (§12 L1–L4). |
| **Phishing verdict path untouched** | `POST /analyze`, `decision-v2`, frozen thresholds, models and `evaluation/` are untouched. Agent ingestion calls `record_findings` (`backend/app/services/findings.py`, **verified**) on the server. |

### 0.1 Out of scope for v1

- **No remote action or live response:** the server cannot run commands, query live logs,
  fetch files, inspect processes or push scripts to an endpoint.
- **No blocking, quarantine or deletion:** neither the agent nor the server blocks network
  connections, modifies the Windows Firewall or hosts file, kills processes, or moves,
  quarantines or deletes any file.
- **No silent auto-update or background privileged service:** updates are explicit local
  package upgrades verified against a pinned manifest (§4.5).
- **No browser-history collection:** the stateless local browser extension
  ([browser-extension-v1](browser-extension-v1.md)) remains separate and never sends visited
  URLs or Findings to the LAN server.

---

## 1. Local engines and non-administrator execution

### 1.1 Engines run locally on the endpoint

The agent reuses the three endpoint engines in process, without changing their rules,
constants, lock files or frozen models:

| Engine | Design reference | Local input on the endpoint | Pseudonyms and indicators emitted on the wire |
| --- | --- | --- | --- |
| `host.windows` | [host-engine-v1](host-engine-v1.md) | User-readable `.evtx` exports in a user-accessible folder | `host_ref` and `account_ref` via `ETIS_HOST_PSEUDONYM_KEY` (`hmac:<32 hex>`, or `sid:S-1-5-18/-19/-20` for well-known service principals), normalised through `app.core.device_names.local_device_name`; hash-only `ip`, `domain`, `url`, `hash` indicators |
| `malware.files` | [malware-engine-v1](malware-engine-v1.md) | User-readable PE files in user-selected folders (e.g. `%USERPROFILE%\Downloads`, `%LOCALAPPDATA%\Programs`, `%ProgramFiles%`) read in place with shared access | `path_ref` via `ETIS_MALWARE_PSEUDONYM_KEY`, location class (`downloads`, `user_programs`, `program_files`, …), size band, PE type; hash-only `hash` (`sha256`) indicator; plus `device_ref` (`hmac:<32 hex>`) injected into `evidence.details` via the shared `app.core.device_names.attach_device_ref(finding, host_key)` helper ([core v2](core-v2.md) §3.2, §3.6) |
| `network.windows` | [network-windows-v1](network-windows-v1.md) | User-readable connection snapshots (`GetExtendedTcpTable` via `ctypes`), and user-readable exported DNS Client `.evtx` / `pfirewall.log` when present | `device_ref` (= `host_ref`, `ETIS_HOST_PSEUDONYM_KEY` via `local_device_name()`), `account_ref`; hash-only `ip`, `domain`, `hash` indicators |

### 1.2 Non-administrator visibility, honest coverage and optional IT log-export policy

Running as a standard Windows user imposes OS access boundaries (all Windows default channel
and API permissions below are **to verify** on Microsoft Learn, §12 W1–W5):

1. **Event logs (`host.windows`, `network.windows`):**
   - The `Security` event log and default `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`
     require administrator rights (or explicit `Event Log Readers` / file ACL configuration
     by the company administrator outside ETIS; **to verify**, §12 W1–W2).
   - Whether a standard user can read `System`, `Microsoft-Windows-PowerShell/Operational`,
     `Microsoft-Windows-Windows Defender/Operational`,
     `Microsoft-Windows-TaskScheduler/Operational` and
     `Microsoft-Windows-DNS-Client/Operational` (when already enabled) is **to verify** (§12 W1).
   - The agent **never** changes channel ACLs, enables logs (`wevtutil sl`) or elevates. Any
     channel or file that is absent or returns `PermissionError` is recorded in the batch's
     coverage report as `not_visible` (with the affected detections H1–H13 or N1–N9 listed as
     `not_visible`), never as "0 findings".
   - **Optional company IT log-export policy (owner decision Q4, §11.1):** Where an
     organisation wants full host and firewall visibility without giving the ETIS agent
     administrator rights, a company IT administrator may configure their own separate
     Windows administrative task (outside ETIS) to periodically export `Security.evtx`,
     `Microsoft-Windows-DNS-Client/Operational` (`dns.evtx`) and `pfirewall.log` into a local
     folder with read-only permissions for the signed-in standard user. The ETIS agent never
     creates, manages or elevates for that task; it only reads the user-accessible files in
     place.
2. **Connection snapshots (`network.windows`):**
   - `GetExtendedTcpTable` (`iphlpapi.dll`) is callable from user space (**to verify** whether
     standard users see all TCP rows and PIDs on Windows 10/11, §12 W3), while resolving the
     process image file name for another user's or elevated process's PID may return
     access denied (`process_category: unknown`).
3. **File scans (`malware.files`):**
   - Standard users can read their own profile folders (`Downloads`, `Desktop`, `Documents`,
     `%LOCALAPPDATA%\Programs`) and most of `%ProgramFiles%` / `%SystemRoot%\System32`
     (**to verify**, §12 W4); unreadable files are counted as `unreadable` without aborting.

### 1.3 Endpoint pseudonymisation, shared device-name helpers and server-side re-wrapping

This design uses the two-stage pseudonym model shared with [core v2](core-v2.md) §3.2 and
§3.6 (owner decision Q1, §11.1):

1. **Shared device-name normalisation (`app/core/device_names.py`):**
   - `local_device_name(raw) -> str | None` returns the text before the first dot, stripped
     and lower-cased, or `None` when empty. For "this PC", the source order is fixed across
     the agent and standalone commands: first `socket.gethostname()`, then `COMPUTERNAME`,
     then `platform.node()`.
   - `Pseudonymizer(host_key).host_ref(local_device_name(...))` (**verified** in
     `backend/app/engines/host/pseudonyms.py`) computes the **endpoint ref**:
     `'hmac:' + hmac.new(host_key, f'host\0{normalized}'.encode('utf-8'), hashlib.sha256).hexdigest()[:32]`.
   - `account_ref` keeps `sid:S-1-5-18`, `sid:S-1-5-19` and `sid:S-1-5-20` in clear and
     hashes real user SIDs (`account-sid\0<SID>`) or `domain\name`
     (`account\0<domain>\<name>`) into `'hmac:' + <32 hex>`.
   - For `malware.files`, the agent runner calls the shared helper
     `app.core.device_names.attach_device_ref(finding, host_key)` (also used by standalone
     `scan_files.py`) so malware Findings carry the same endpoint `device_ref` (`hmac:<32 hex>`)
     without altering the frozen malware engine.
2. **Endpoint keys provisioned at pairing:**
   - During pairing (§4.1), the agent receives the company LAN's `ETIS_HOST_PSEUDONYM_KEY`
     (32 random bytes, hex-encoded) and generates a per-device local
     `ETIS_MALWARE_PSEUDONYM_KEY` (32 random bytes, kept on the endpoint only; malware
     `path_ref` never needs to join across different PCs, per
     [malware-engine-v1](malware-engine-v1.md) §6.7).
3. **Server-side re-wrap with `ETIS_SERVER_REF_KEY` (`srv:<32 hex>`):**
   - `scripts/initialize.py` on the server generates a dedicated 32-byte random secret
     `ETIS_SERVER_REF_KEY` into the server's ignored `.env` only when absent, and **never
     overwrites an existing key**. It is **never** sent to any agent, and key rotation is
     out of scope (rotating or losing `ETIS_SERVER_REF_KEY` would split a device's or
     account's stored ref history; the key must be backed up with the server database, per
     [core v2](core-v2.md) §3.2).
   - At pairing (§4.1) and at the single ingestion choke point in `record_findings` (§5.2),
     the server wraps every valid incoming `hmac:<32 hex>` reference using
     `app.core.device_names.wrap_ref`:
     - Device / host ref:
       `'srv:' + HMAC-SHA-256(ETIS_SERVER_REF_KEY, 'device\0' + endpoint_ref)[:32 hex]`
       (36 characters, fits `String(37)`).
     - Account ref:
       `'srv:' + HMAC-SHA-256(ETIS_SERVER_REF_KEY, 'account\0' + endpoint_account_ref)[:32 hex]`
       (well-known `sid:S-1-5-18`, `-19`, `-20` are left unchanged).
   - Only `srv:<32 hex>` device and account references (and well-known `sid:` principals) are
     ever stored in `devices`, `findings.evidence`, or `finding_devices`, and only `srv:`
     references are shown or accepted by the console and operator APIs (§5.3, §7.2). Malware
     `path_ref` remains a local file pseudonym and is not re-wrapped.

---

## 2. Threat model

All security properties of OS storage, TLS pinning and local network boundaries are
**to verify** before implementation (§12 S1–S5).

### 2.1 Assets to protect

1. **Employee and endpoint privacy:** raw Windows event records, command lines, PowerShell
   script text, full DNS/connection history, scanned file contents, file paths, usernames
   and computer names must stay on the endpoint and never reach the LAN server or logs.
2. **Server integrity and multi-device isolation:** one compromised or spoofed endpoint on
   the LAN must not be able to read other devices' Findings, inject Findings under another
   device's identity, flood the server database, or access analyst console endpoints
   (`/incidents`, `/indicators`, `/devices`, `/device-risk`, `/analyze`).
3. **Endpoint safety against a rogue LAN server or MITM:** an attacker on the company LAN
   (ARP/DNS spoofing) or a compromised ETIS server must not be able to execute commands,
   modify files, or push rules/code to any endpoint.

### 2.2 Adversaries and mitigations

| Adversary / threat | Mitigation in this design | Residual limitation (stated honestly) |
| --- | --- | --- |
| **A1. Passive or active LAN eavesdropper / MITM** (ARP spoofing, rogue DHCP/DNS on the company LAN) | All agent–server traffic uses HTTPS. On every connection, the agent checks the server leaf certificate's DER SHA-256 fingerprint against the `primary` (or `next`) pin configured at pairing (§4.2). Plain HTTP, redirects (`3xx`) and unpinned certificates abort the connection before any bearer token or Finding is sent. | Requires the operator to copy the pairing bundle (which contains the pin) over a trusted out-of-band path during initial pairing. |
| **A2. Rogue or compromised LAN server attempting remote control** | The agent has **no command execution, file modification, policy download or rule eval-from-server path**. The server's HTTP response to a batch is strictly a fixed-schema JSON receipt (`accepted_findings`, `duplicate_findings`, `batch_id`); unknown fields or non-JSON bodies are rejected and discarded. | None for remote execution via the protocol; updates are local and manual (§4.5). |
| **A3. Malicious LAN host without a device token** | Ingestion endpoints require a per-device bearer token issued via a one-use, short-lived pairing secret (`POST /agent/v1/pair`). Pairing secrets expire (default 15 minutes), lock out after failed attempts, and bind to one device. | An attacker who steals an unused pairing code before the employee uses it could pair a rogue device; operators can see `paired_at` and revoke unknown devices immediately. |
| **A4. Compromised paired endpoint spamming or spoofing another device** | Each device gets a distinct bearer token (`agent_token`), scoped only to `/agent/v1/batches`, `/agent/v1/heartbeat` and `/agent/v1/unpair` (never the general `ETIS_API_KEY`). On every batch, the server validates that every Finding's incoming `device_ref` / `host_ref` has the `^hmac:[0-9a-f]{32}$` wire format, wraps it with `wrap_ref(incoming_hmac, "device")` using `ETIS_SERVER_REF_KEY`, and compares the wrapped `srv:` value to the token-bound `devices.device_ref` (`srv:`) with `hmac.compare_digest` before anything is stored (§5.2 rule 3); any mismatch rejects the entire batch (`422 device_ref_mismatch`). Per-device rate and payload limits apply. | A compromised endpoint can emit fabricated Findings *for its own `device_ref`* (which can raise its own per-device risk score, never another device's, per [core v2](core-v2.md) §3.6) or reuse known public indicator hashes so its Findings correlate with existing incidents. Console views show which `device_ref` (`srv:`) contributed each Finding, mark Findings from a revoked device as `"from a revoked device"`, and offer an optional manual purge after a chosen timestamp (§5.3, §7.2). |
| **A5. Malware running as the same Windows user on the endpoint** | The agent runs as the standard user, so same-user malware has the same OS privileges. The agent never stores raw logs in its queue, and the server only accepts `finding-v1` payloads for that device's token. Because the server re-wraps every device and account ref with `ETIS_SERVER_REF_KEY` (which stays on the server and is never sent to any agent) into `srv:<32 hex>` before storage, **a leaked `ETIS_HOST_PSEUDONYM_KEY` from one compromised endpoint cannot be used to dictionary-guess or confirm computer names or account names against stored `srv:` refs** seen in the console or database backups ([core v2](core-v2.md) §3.2, §3.6). | **Cannot defend against same-user or admin compromise on the endpoint itself:** local malware running under the same Windows account can read `%LOCALAPPDATA%\ETIS-Agent\`, extract that device's `agent_token` and `ETIS_HOST_PSEUDONYM_KEY` (even if wrapped with DPAPI `CryptProtectData` under `CRYPTPROTECT_UI_FORBIDDEN`, which protects against other OS users/offline disk reads, not same-user processes; **to verify**, §12 S3), or kill/skip the user-space agent. If an attacker compromises *both* `ETIS_HOST_PSEUDONYM_KEY` and the server's `.env` (`ETIS_SERVER_REF_KEY`), they could dictionary-guess low-entropy host/account names. |
| **A6. Privacy leakage from Findings to the server operator** | Raw content, paths, usernames and unalerted DNS/connection history never leave the PC. `device_ref`, `account_ref` and `path_ref` are keyed HMAC-SHA-256 references (`srv:` stored on the server for device and account refs). | Alerted remote IPs, alerted registered domains and alerted file SHA-256 hashes are sent as unkeyed SHA-256 `value_hash` (`value=None`) so `record_findings` can correlate across feeds and devices ([core-v1](core-v1.md) §2.2, [network-windows-v1](network-windows-v1.md) §7). Unkeyed SHA-256 of an IPv4 address or known domain is reversible by brute force for those **alerted** destinations only. |

---

## 3. Data flow diagram (text)

```text
+-----------------------------------------------------------------------------------+
| EMPLOYEE WINDOWS PC (Standard user account — NO administrator rights)             |
|                                                                                   |
|  Local read-only sources (never modified, never uploaded):                        |
|   +------------------------+  +-----------------------+  +---------------------+  |
|   | User-readable .evtx    |  | User-selected PE      |  | TCP snapshot table  |  |
|   | (Host & DNS exports)   |  | files (read in place) |  | + pfirewall.log     |  |
|   +-----------+------------+  +-----------+-----------+  +----------+----------+  |
|               |                           |                         |             |
|               v                           v                         v             |
|   +------------------------+  +-----------------------+  +---------------------+  |
|   |     host.windows       |  |     malware.files     |  |   network.windows   |  |
|   | (H1-H13 + pinned Sigma)|  | (Hashes + YARA + ML)  |  | (N1, N3-N9 + lists) |  |
|   +-----------+------------+  +-----------+-----------+  +----------+----------+  |
|               |                           |                         |             |
|               +---------------------------+-------------------------+             |
|                                           |                                       |
|     In-memory events/files destroyed      v                                       |
|   +---------------------------------------------------------------------------+   |
|   | Local Endpoint Sanitizer & Pseudonymizer (app/core/device_names.py)       |   |
|   |  - host_ref / device_ref := hmac:HMAC(ETIS_HOST_PSEUDONYM_KEY, host)      |   |
|   |    (via local_device_name() & attach_device_ref() on malware Findings)    |   |
|   |  - account_ref := hmac:HMAC(ETIS_HOST_PSEUDONYM_KEY, acct) or sid:S-1-5-* |   |
|   |  - path_ref := hmac:HMAC(ETIS_MALWARE_PSEUDONYM_KEY, path)                |   |
|   |  - Indicators := SHA-256 value_hash only (value = null)                   |   |
|   |  - Validates strict Finding (finding-v1) + non-content coverage report    |   |
|   +---------------------------------------+-----------------------------------+   |
|                                           |                                       |
|                                           v                                       |
|   +---------------------------------------------------------------------------+   |
|   | Bounded Offline Queue (%LOCALAPPDATA%\ETIS-Agent\queue.db, user ACL only) |   |
|   |  - Stores only sanitised finding-v1 batches (max 10 MB / 5,000 Findings)  |   |
|   +---------------------------------------+-----------------------------------+   |
+-------------------------------------------|---------------------------------------+
                                            |
                                            | HTTPS over company LAN only
                                            | - Literal RFC 1918 / ULA / local-net check
                                            | - Pinned leaf cert DER SHA-256 (primary/next)
                                            | - Authorization: Bearer <per-device token>
                                            | - Wire refs are hmac:<32 hex> (one-way push)
                                            v
+-----------------------------------------------------------------------------------+
| COMPANY LAN ETIS SERVER (holds server-only ETIS_SERVER_REF_KEY in ignored .env)   |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | Agent Router (/agent/v1/pair, /agent/v1/batches, /agent/v1/heartbeat)     |   |
|   |  - Verifies SHA-256(token) in `devices` table (status == 'active')        |   |
|   |  - Validates wire refs match ^hmac:[0-9a-f]{32}$ (rejects srv: on wire)   |   |
|   |  - Checks wrap_ref(incoming hmac:, "device") == devices.device_ref (srv:) |   |
|   |  - Enforces Finding.indicators[*].value is None (hash-only)               |   |
|   |  - Deduplicates by (device_id, batch_id) and Finding.id                   |   |
|   +---------------------------------------+-----------------------------------+   |
|                                           |                                       |
|                                           v                                       |
|   +---------------------------------------------------------------------------+   |
|   | Core v1/v2 Services (record_findings with wrap_refs + finding_devices)    |   |
|   |  - wrap_refs() converts device_ref, host_ref & account_ref to srv:<32 hex>|   |
|   |  - Writes finding_devices(finding_id, device_ref='srv:...', 'agent')      |   |
|   |  - Upserts hash-only indicators & sightings (source.kind = 'sensor')      |   |
|   |  - Validates ATT&CK v20.0 IDs & correlates Findings into Incidents        |   |
|   +---------------------------------------+-----------------------------------+   |
|                                           |                                       |
|                                           v                                       |
|   +---------------------------------------------------------------------------+   |
|   | SOC Console (Same-origin Node proxy + React UI, Arabic & English)         |   |
|   |  - "Devices (LAN)" tab (/devices, /devices/{id}) + core v2 Risk panel     |   |
|   |  - Shows & accepts srv:<32 hex> refs only; de-fanged <IndicatorValue />   |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
```

---

## 4. Agent lifecycle: pairing, transport, offline queue, updates and uninstall

### 4.1 Pairing and authentication

1. **Operator creates a one-use pairing invitation on the server:**
   - In the SOC console (`/devices`) or via a server CLI command
     (`python data/scripts/manage_agent_devices.py create-invite --label "Dept-01"`), the
     operator generates a one-use pairing secret (32 random bytes from `secrets.token_urlsafe`,
     displayed once and stored only as a SHA-256 digest in `device_pairing_tokens` with an
     expiry of 15 minutes; parameters to freeze before implementation).
   - The console displays a copyable pairing bundle containing:
     - `server_url`: e.g. `https://192.168.1.50:8443` (must be a literal LAN IP or pinned
       LAN host);
     - `primary_cert_sha256` (and optional `next_cert_sha256`): the 64-hex-character SHA-256
       fingerprint of the server's DER leaf TLS certificate;
     - `pairing_code`: the one-use secret;
     - `host_pseudonym_key`: the 64-hex-character `ETIS_HOST_PSEUDONYM_KEY` (entered at the
       interactive prompt or read from a temporary local file deleted after pairing, never
       passed on the process command line where other local processes could read it).
     - `ETIS_SERVER_REF_KEY` is **never** included in the pairing bundle or sent to an agent.
2. **User runs `etis_agent pair` on the Windows endpoint (no admin rights):**
   - Displays the bilingual PDPL 151/2020 employee notice (§7.4) in the terminal and requires
     an explicit confirmation (`yes` / `موافق`) before making any network connection.
   - Determines the local computer name via `app.core.device_names.local_device_name()`
     (source order: `socket.gethostname()`, then `COMPUTERNAME`, then `platform.node()`),
     computes the endpoint reference `device_ref = Pseudonymizer(host_key).host_ref(name)`
     (`hmac:<32 hex>`), and generates a random UUID4 `agent_instance_id` and local
     `ETIS_MALWARE_PSEUDONYM_KEY`.
   - Connects to `POST /agent/v1/pair` over HTTPS, verifying the server certificate against
     `primary_cert_sha256` (or `next_cert_sha256`, §4.2).
   - Sends `{schema_version: "agent-pair-v1", pairing_code, device_ref, agent_instance_id,
     agent_version, notice_version_ack: "pdpl-notice-v1"}`. Never sends the computer name,
     username, OS serial number or MAC address.
3. **Server wraps `device_ref` to `srv:` and exchanges the pairing code for a token:**
   - Validates that the incoming `device_ref` matches `^hmac:[0-9a-f]{32}$` (an incoming
     `srv:` prefix is rejected with `400 invalid_input`).
   - Wraps the endpoint reference with the server-only key using the shared helper
     `stored_ref = wrap_ref(device_ref, "device")` (`srv:<32 hex>`, [core v2](core-v2.md)
     §3.2, §3.6). If `ETIS_SERVER_REF_KEY` is missing on the server, pairing fails closed
     with `503 server_ref_key_missing` and stores nothing.
   - Atomically marks the pairing code used, creates or updates the `devices` row for
     `stored_ref` (`devices.device_ref` stores **only** `srv:<32 hex>`, never `hmac:`), mints
     a 32-byte random `agent_token`, stores only `token_hash = sha256(agent_token)` in
     `devices`, and returns `{schema_version: "agent-pair-v1", device_id, agent_token,
     server_instance_id}`. The pairing response **never echoes `device_ref`**, because the
     endpoint has no use for the `srv:` form ([core v2](core-v2.md) §3.6 item 2).
   - If a device with the same wrapped `srv:` `device_ref` was previously paired, re-pairing
     rotates `token_hash` and `agent_instance_id`, sets `status = 'active'`, and records a
     `repaired` audit event.
4. **Local credential storage on the endpoint:**
   - Stored under `%LOCALAPPDATA%\ETIS-Agent\config.json` and `secrets.bin`.
   - On creation, the agent restricts the directory ACL to the current Windows user SID
     (`icacls` or Win32 security descriptor; exact API behavior **to verify**, §12 S4) and
     protects `agent_token`, `ETIS_HOST_PSEUDONYM_KEY` and `ETIS_MALWARE_PSEUDONYM_KEY`
     with Windows DPAPI (`CryptProtectData` via `ctypes` with `CRYPTPROTECT_UI_FORBIDDEN`;
     exact Win32 call signature and behavior **to verify**, §12 S3).
5. **Revocation and rotation (owner decision Q3, §11.1):**
   - The operator can revoke a device at any time (`POST /devices/{id}/revoke`), setting
     `status = 'revoked'` and clearing `token_hash`. Any subsequent request from that token
     receives `401 {"error": "device_revoked"}`, upon which the agent stops sending and
     marks its local state `revoked`.
   - Existing Findings from a revoked device are **kept** by default and marked `"from a
     revoked device"` (`device_revoked: true`) in the console and API. If the operator
     determines that Findings submitted on or after a compromise timestamp are untrusted, a
     separate explicit operator action (`POST /devices/{id}/purge-findings`) purges that
     device's Findings and batches on or after the chosen timestamp; this purge is **never
     automatic**.

### 4.2 Transport: HTTPS on the LAN with a pinned server certificate

- **Target locality gate:** Before opening a socket, the agent parses `server_url` and
  verifies that the scheme is `https`, the port is explicit, and the host is a literal IP
  for which `app.engines.host.pseudonyms.locality(ip, local_nets)` returns `'local'`
  (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, IPv6 ULA `fc00::/7`,
  link-local, loopback in local tests, or `--local-net`). Public IP addresses and non-HTTPS
  schemes are refused before any connection (`transport_target_not_lan`). If a LAN hostname
  is permitted by configuration, its resolved IP is checked against `locality(...) == 'local'`
  before connecting (**to verify** socket connect-by-IP vs SNI behavior in Python `ssl`,
  §12 S2).
- **Certificate pinning (leaf certificate DER SHA-256 with `primary` + `next` pins; owner decision Q5, §11.1):**
  - The server runs with a local self-signed or company-CA TLS certificate generated offline
    by the operator (e.g. `scripts/generate_lan_cert.py`, valid for the server's LAN IP in
    `subjectAltName`).
  - On every TLS handshake, the agent uses Python's standard-library `ssl.SSLContext`
    (minimum TLS 1.3 or TLS 1.2; exact Python 3.12 `ssl` flags and `getpeercert(binary_form=True)`
    verification timing **to verify**, §12 S1–S2), retrieves the peer's DER-encoded leaf
    certificate (`ssock.getpeercert(binary_form=True)`) **before** sending any HTTP request
    header or body, and checks `hashlib.sha256(der_bytes).hexdigest()` against
    `primary_cert_sha256` (and `next_cert_sha256` when configured) using
    `hmac.compare_digest`.
  - If the digest matches neither pin, the connection is closed immediately before any HTTP
    bytes (including the `Authorization` header) are written, and the agent records
    `tls_pin_mismatch`.
  - Supporting two pins (`primary_cert_sha256` and optional `next_cert_sha256`) uses only the
    Python standard library and lets the operator pre-distribute a replacement certificate
    fingerprint before rotating the server certificate.
- **HTTP hardening:** No redirects followed (`3xx` treated as an error), no cookies sent or
  stored, system HTTP proxies ignored (`urllib.request.ProxyHandler({})`), `Cache-Control:
  no-store`, request timeout 15 s, maximum request body 1 MB.

### 4.3 Offline queue with size limit

When a run produces Findings (or a coverage/health heartbeat) and the LAN server is
unreachable, times out, fails TLS or returns `429` / `5xx`:

1. **Sanitise before queuing:** Only validated `agent-batch-v1` JSON objects (containing
   `finding-v1` Findings with `value=None` indicators and endpoint `hmac:` pseudonyms, plus
   coverage counts) are written to `%LOCALAPPDATA%\ETIS-Agent\queue.db` (a local SQLite table
   `queued_batches(batch_id TEXT PRIMARY KEY, created_at TEXT, max_severity TEXT,
   finding_count INT, payload_bytes INT, payload_json TEXT, attempts INT, last_error TEXT)`).
   Raw logs, events and file paths never touch the queue.
2. **Hard size and count limits:**
   - Maximum queue size on disk: **10 MB** of `payload_bytes` (configurable up to 25 MB).
   - Maximum queued batches: **100 batches** or **5,000 Findings** (whichever is reached
     first), at most **100 Findings per batch** and **512 KB per batch**.
   - Maximum age in queue: **14 days** (matches `ETIS_CORRELATION_WINDOW_DAYS`; older queued
     batches are expired locally and counted in `queue_expired_findings_count`).
3. **Overflow rule (severity-preserving eviction):**
   - If adding a new batch would exceed 10 MB, 100 batches or 5,000 Findings, the queue
     first evicts the oldest queued batches whose `max_severity` is strictly lower than the
     new batch's `max_severity` (evicting `info`, then `low`, then `medium`).
   - If the queue is still full (for example full of `high` batches), the oldest batch of
     equal severity is evicted so the newest evidence is kept, and the agent increments
     persistent counters `queue_overflow_batches_dropped` and
     `queue_overflow_findings_dropped`.
   - Those counters are sent in the next successful batch's `coverage.queue_status` so the
     SOC console displays a visible `queue_overflow_dropped` warning for that device rather
     than silently missing data.
4. **Idempotent flush and retry:**
   - On the next run (or `etis_agent flush`), queued batches are sent in FIFO order (`created_at`).
   - Each batch carries its stable UUID4 `batch_id` and each Finding carries its stable UUID4
     `id`. If a connection drops after the server commits a batch, the retry sends the same
     `batch_id` and `Finding.id`s; the server recognises the duplicate and returns `200 OK`
     with `duplicate_batch: true`, allowing the agent to delete the queued row.
   - Permanent rejection codes (`400 invalid_input`, `401 device_revoked`, `413 limit_exceeded`,
     `422 device_ref_mismatch`, `422 device_ref_conflict`, `422 ref_prefix_invalid`,
     `422 plaintext_indicator_forbidden`, `422 disallowed_evidence_field`) are **not**
     retried: `401 device_revoked` halts the agent until re-paired; `400`/`422` removes the
     malformed batch and records `batch_rejected_by_server` in local diagnostics (reason code
     only, no payload).

### 4.4 Execution model: no silent services, scheduled tasks or startup entries

- **Default mode (manual / on-demand):** The user runs the agent explicitly in their own
  user session:
  ```text
  python -m etis_agent run [--host-evtx <dir>] [--scan-path <dir>] [--network-logs <dir>] [--snapshot-tcp]
  ```
- **Optional user-chosen scheduling:**
  - The agent never registers a Windows Service, never writes to `HKLM`, and never creates a
    scheduled task or `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry during
    installation or pairing.
  - If the user wants periodic runs during their own sign-in session, they may either create
    their own Windows Task Scheduler task under their user account, or run the explicit
    opt-in command `python -m etis_agent schedule --enable --interval-minutes 60`, which
    prompts for confirmation and creates a current-user-only scheduled task (or `HKCU` entry;
    non-admin `schtasks.exe /Create` vs `HKCU\...\Run` behavior **to verify**, §12 W5)
    labelled `ETISUserAgent` running at `LeastPrivilege`.
  - `python -m etis_agent schedule --disable` removes it immediately without admin rights.

### 4.5 Update policy

- **No automatic or remote updates:** The agent has no background updater, downloads nothing
  from the internet or the LAN server, and never executes code received over the network.
- **Version and lock reporting:** Every batch and heartbeat reports `agent_version` (e.g.
  `agent-v1.0.0`) and the local engine version strings (`host.windows`, `malware.files`,
  `network.windows`), which embed the SHA-256 prefixes of the local rule manifests, Sigma
  lock, YARA lock, hash-list lock, network blocklist lock and model lock
  ([host-engine-v1](host-engine-v1.md) §6.1, [malware-engine-v1](malware-engine-v1.md) §6.1,
  [network-windows-v1](network-windows-v1.md) §6.1).
- **Staleness visibility:** The LAN server compares the device's reported lock prefixes
  against its own pinned lock files (`data/*-lock.json`) and shows `agent_outdated` or
  `locks_stale` in the console's per-device view when they differ, prompting the user or IT
  operator to upgrade the local package manually from a hash-verified offline bundle.

### 4.6 Uninstall

Running `python -m etis_agent uninstall` (no administrator rights needed):

1. If the LAN server is reachable and the device is paired, optionally sends
   `POST /agent/v1/unpair` with its bearer token so the server marks the device
   `revoked` (`revoked_reason = 'user_uninstalled'`). If the server is unreachable, local
   uninstall proceeds immediately without blocking.
2. Removes the opt-in user scheduled task / `HKCU` startup entry if the user had enabled it.
3. Deletes `%LOCALAPPDATA%\ETIS-Agent\` (including `secrets.bin`, `config.json` and
   `queue.db`).
4. Leaves zero background processes, drivers, services, registry keys or files outside the
   project checkout.

---

## 5. API endpoints

All routes below are **new proposals** for v1. Server routes fall into two strictly separated
groups:

- **Agent ingestion routes (`/agent/v1/*`)**: authenticate only with a per-device bearer
  token (`Authorization: Bearer <agent_token>`, except `/agent/v1/pair` which uses a one-use
  `pairing_code`), accept only endpoint `hmac:` device/account references on the wire, never
  authenticate with `X-API-Key`, and are **never** exposed through the browser proxy
  (`etis-frontend/server.mjs`).
- **Operator console routes (`/devices/*`)**: authenticate with `X-API-Key` through the
  existing same-origin Node proxy (`/api/devices/*`), matching `/incidents`,
  `/malware/scans`, `/network/windows/imports` and core v2's `/device-risk`. They expose and
  accept **only `srv:<32 hex>`** device and account references (plus well-known `sid:`
  service principals), never `hmac:` ([core v2](core-v2.md) §3.6 item 6).

All responses carry `Cache-Control: no-store`. Errors use `{error, detail}` with fixed
reason codes and never echo submitted payloads.

### 5.1 Agent-to-server endpoints (LAN HTTPS)

| Method & path | Auth | Request body (strict, `extra='forbid'`) | Response | Error codes |
| --- | --- | --- | --- | --- |
| `POST /agent/v1/pair` | One-use `pairing_code` (rate-limited per source IP) | `{schema_version: "agent-pair-v1", pairing_code: str, device_ref: "hmac:<32 hex>", agent_instance_id: UUID4, agent_version: str, notice_version_ack: "pdpl-notice-v1"}` | `200 OK`: `{schema_version: "agent-pair-v1", device_id: int, agent_token: str, server_instance_id: str}` (`device_ref` is wrapped to `srv:` and stored, never echoed) | `400 invalid_input`, `400 notice_ack_required`, `401 pairing_code_invalid`, `401 pairing_code_expired`, `429 rate_limited`, `503 server_ref_key_missing` |
| `POST /agent/v1/batches` | `Authorization: Bearer <agent_token>` | `{schema_version: "agent-batch-v1", batch_id: UUID4, sent_at: AwareDatetime, agent_version: str, engine_versions: dict[str, str], coverage: AgentCoverage, findings: list[Finding]}` (0 to 100 `finding-v1` Findings) | `200 OK`: `{schema_version: "agent-batch-v1", batch_id: UUID4, duplicate_batch: bool, accepted_findings: int, duplicate_findings: int, received_at: AwareDatetime}` | `400 invalid_input`, `401 token_invalid`, `401 device_revoked`, `413 limit_exceeded`, `422 device_ref_mismatch`, `422 device_ref_conflict`, `422 ref_prefix_invalid`, `422 plaintext_indicator_forbidden`, `422 disallowed_evidence_field`, `429 rate_limited`, `503 server_ref_key_missing`, `503 database_unavailable` |
| `POST /agent/v1/heartbeat` | `Authorization: Bearer <agent_token>` | `{schema_version: "agent-heartbeat-v1", sent_at: AwareDatetime, agent_version: str, engine_versions: dict[str, str], coverage: AgentCoverage}` | `200 OK`: `{schema_version: "agent-heartbeat-v1", received_at: AwareDatetime}` | Same `400`, `401`, `429`, `503` codes |
| `POST /agent/v1/unpair` | `Authorization: Bearer <agent_token>` | `{schema_version: "agent-unpair-v1"}` | `200 OK`: `{status: "revoked"}` | `401 token_invalid`, `401 device_revoked` |

### 5.2 Server-side validation gates on `POST /agent/v1/batches`

Before calling `record_findings(db, new_findings)`, the server enforces:

1. **Token and device status:** `sha256(agent_token)` must match an existing `devices` row
   with `status == 'active'`.
2. **Schema and size limits:** Body ≤ 512 KB, `len(findings) <= 100`, every Finding validates
   against `app.core.findings.Finding` (`schema_version == 'finding-v1'`,
   `domain in ('host', 'malware', 'network')`, `engine.name in ('host.windows',
   'malware.files', 'network.windows')`).
3. **Wrapped device identity binding (`device_ref_mismatch`, [core v2](core-v2.md) §3.6 item 3):**
   Every Finding in the batch must carry `device_ref` or `host_ref` in `evidence.details` in
   the endpoint wire format `^hmac:[0-9a-f]{32}$` (if any ref on the wire starts with
   `srv:`, reject the batch with `422 ref_prefix_invalid`; if both `device_ref` and
   `host_ref` are present on one Finding and differ, reject with `422 device_ref_conflict`).
   The server wraps the incoming `hmac:` value with `wrap_ref(incoming_hmac, "device")` using
   `ETIS_SERVER_REF_KEY` (failing closed with `503 server_ref_key_missing` if the server key
   is absent) and compares the wrapped `srv:<32 hex>` string against the authenticated
   device's stored `devices.device_ref` (`srv:<32 hex>`) using `hmac.compare_digest`. Any
   mismatch rejects the entire batch with `422 device_ref_mismatch` before anything is
   stored.
4. **Hash-only indicators (`plaintext_indicator_forbidden`):** Every `IndicatorRef` in
   `finding.indicators` must have `value is None`. If any indicator carries a non-null
   `value`, the entire batch is rejected with `422 plaintext_indicator_forbidden`.
5. **Evidence allowlist (`disallowed_evidence_field`):** For each engine, `evidence.details`
   may contain only the non-content keys defined in [host-engine-v1](host-engine-v1.md) §6.5,
   [malware-engine-v1](malware-engine-v1.md) §6.6 and
   [network-windows-v1](network-windows-v1.md) §6.5 (plus `device_ref`). On the wire,
   `device_ref`, `host_ref` and `path_ref` must match `^hmac:[0-9a-f]{32}$`, and
   `account_ref` must match `^hmac:[0-9a-f]{32}$` or `^sid:S-1-5-(18|19|20)$`. Any unknown
   key, any `srv:` prefix on the wire, or any string value that fails its format check
   rejects the whole batch with `422 disallowed_evidence_field` (or `422 ref_prefix_invalid`).
6. **Source reference normalisation and server-side re-wrap in `record_findings`:** The
   server sets each accepted Finding's `source` to
   `SourceRef(kind='sensor', ref=f'agent_devices:{device.id}:{batch_id}')` and passes the
   Findings to `record_findings(db, new_findings)`. As its first step ([core v2](core-v2.md)
   §3.2), `record_findings` calls `wrap_refs(finding)` to replace `details.device_ref`,
   `details.host_ref` and `details.account_ref` with their `srv:<32 hex>` forms (leaving
   well-known `sid:` account refs and `path_ref` unchanged) and writes a row into
   `finding_devices(finding_id, device_ref='srv:...', attributed_by='agent')`. No `hmac:`
   device or account ref is ever stored.
7. **Idempotency:** If `(device.id, batch_id)` already exists in `agent_batches`, return
   `duplicate_batch=True` without re-inserting. Any individual `Finding.id` already present
   in `findings` is skipped and counted in `duplicate_findings`.

### 5.3 Operator console endpoints (`/devices/*` via `/api/devices/*`)

All device and account references returned or accepted by these endpoints use the stored
`srv:<32 hex>` format (or `sid:S-1-5-18/-19/-20` for well-known service principals), never
`hmac:` ([core v2](core-v2.md) §3.6 item 6).

| Method & path | Purpose |
| --- | --- |
| `GET /devices?status=&limit=&offset=` | Paginated device list: `id`, `device_ref` (`srv:<32 hex>`), `display_label`, `status` (`active`, `revoked`), `agent_version`, `engine_versions`, `paired_at`, `last_seen_at`, `last_coverage`, `notice_version_ack`, Finding counts by severity/domain, open incident count. |
| `GET /devices/{id}` | Per-device detail: device metadata (`device_ref` in `srv:` form), coverage breakdown (`visible` vs `not_visible` sources and detections, `queue_overflow` counters), recent batches (`agent_batches`), paginated Findings across `host.windows`, `malware.files` and `network.windows` for this `device_ref` (with `account_ref` in `srv:`/`sid:` form and `from_revoked_device: bool`), and linked Incidents. |
| `POST /devices/pairing-invites` | `{display_label?: str}` → creates a one-use pairing invitation (`expires_at`, 15 min) and returns `{invite_id, pairing_code, expires_at, primary_cert_sha256, next_cert_sha256}` once. `display_label` is validated against `^[A-Za-z0-9_.-]{1,64}$` so operators cannot accidentally paste an email address, domain login or file path. |
| `PATCH /devices/{id}` | `{display_label: str}` (same strict pattern `^[A-Za-z0-9_.-]{1,64}$`). |
| `POST /devices/{id}/revoke` | `{reason?: str}` → sets `status = 'revoked'`, clears `token_hash`, records `revoked_at` and writes an audit event. Existing Findings from the device are kept and marked `from_revoked_device: true` (owner decision Q3, §11.1). |
| `POST /devices/{id}/purge-findings` | `{since: AwareDatetime, reason: str}` → explicit, never-automatic operator action on a `revoked` device (owner decision Q3, §11.1): deletes Findings and `agent_batches` received from this device with `received_at >= since` (or `observed_at >= since`) via `_expire_findings`, cleans up orphan hash-only indicators, and writes `findings_expired` events on affected Incidents. Refuses with `409 device_not_revoked` if the device is still active. |

---

## 6. ATT&CK v20.0, Findings and cross-device correlation

- **No new ATT&CK mapping on the transport layer:** The agent transport and server ingestion
  layer add no ATT&CK techniques of their own. Each Finding carries the techniques emitted
  locally by `host.windows` ([host-engine-v1](host-engine-v1.md) §5),
  `malware.files` ([malware-engine-v1](malware-engine-v1.md) §5) or
  `network.windows` ([network-windows-v1](network-windows-v1.md) §5), and the server's
  `record_findings` validates every technique ID against the local pinned ATT&CK v20.0
  catalogue (`data/attack-lock.json`, prefix `2339a3c36353`, **verified**).
- **Cross-engine and cross-device correlation through `record_findings`:**
  - **Same device across engines:** On one employee PC, a suspicious PE flagged by
    `malware.files` (`scanned_file` hash), executed in `host.windows` (`executed_file` hash)
    and making a Sysmon 3 connection in `network.windows` (`connecting_process` hash) share
    the same SHA-256 `hash` indicator and automatically correlate into **one incident**.
  - **Across devices on the LAN:** Two employee PCs querying the same phishing or C2
    registered domain (`resolved_name`) or connecting to the same non-local C2 IP
    (`remote_endpoint`) within `ETIS_CORRELATION_WINDOW_DAYS` (14 days) join **one
    incident** through their shared hash-only indicator, subject to core v1 exclusions
    (shared hosting, official brand domains, official brand hotlines, `correlation_stoplist`).
  - **`device_ref` never pivots incidents:** Two unrelated Findings on the same PC that share
    no indicator do not merge into one incident ([host-engine-v1](host-engine-v1.md) §6.6,
    [network-windows-v1](network-windows-v1.md) §6.6); instead, the per-device console view
    (`/devices/{id}`) and core v2's `finding_devices` table group all Findings of that
    `srv:<32 hex>` `device_ref` side by side.

---

## 7. Server side: tables, console view, retention and PDPL 151/2020 notice

### 7.1 Database tables (Alembic migration `010_agent_devices`, or next free number)

Migration `009_finding_devices` is reserved by [core v2](core-v2.md) §3.2 and §3.6, so the
agent tables use **`010_agent_devices`** (or the next free revision when it lands, tested for
upgrade from `009`):

| Table | Key columns |
| --- | --- |
| `devices` | `id` (PK), `device_ref` (String(37), unique, always `srv:<32 hex>`, 36 characters), `display_label` (String(64), nullable), `token_hash` (String(64), nullable, unique index), `agent_instance_id` (String(36)), `status` (`active \| revoked`), `agent_version` (String(64)), `engine_versions` (JSON), `last_coverage` (JSON), `notice_version_ack` (String(32)), `paired_at` (DateTime), `last_seen_at` (DateTime), `revoked_at` (DateTime, nullable), `revoked_reason` (String(100), nullable). |
| `device_pairing_tokens` | `id` (PK), `code_hash` (String(64), unique), `display_label` (String(64), nullable), `created_at` (DateTime), `expires_at` (DateTime), `used_at` (DateTime, nullable), `failed_attempts` (Integer, default 0), `device_id` (FK `devices.id`, nullable). |
| `agent_batches` | `id` (PK), `batch_id` (String(36)), `device_id` (FK `devices.id`), `sent_at` (DateTime), `received_at` (DateTime), `agent_version` (String(64)), `engine_versions` (JSON), `coverage` (JSON), `accepted_findings` (Integer), `duplicate_findings` (Integer); unique `(device_id, batch_id)`, index on `received_at`. |

No existing table schema is altered. Findings use existing `findings.source_kind = 'sensor'`
and `findings.source_ref = 'agent_devices:<device_id>:<batch_id>'`, and `record_findings`
populates core v2's `finding_devices` table with the wrapped `srv:<32 hex>` `device_ref` and
`attributed_by = 'agent'`.

### 7.2 Per-device view in the SOC console

Added to the existing React app (`etis-frontend`) in Arabic and English (`ar.json`,
`en.json`) with RTL support, sharing the **Devices** tab (`/devices`) with [core v2](core-v2.md)
§3.5 (whichever design lands first creates the tab, and the other extends it) and rendering
any feed-matched indicator plaintext exclusively through core v2's de-fanging
`<IndicatorValue />` component (`defang-v1`, [core v2](core-v2.md) §4.4):

1. **Devices list tab (`/devices`):**
   - Summary cards: active devices, stale devices (no heartbeat/batch in > 24 h), devices
     with `not_visible` sources or `queue_overflow`, revoked devices.
   - Table of devices showing `display_label` (if set), truncated stored `device_ref`
     (`srv:a1b2c3d4…`, never `hmac:`), status badge (`active`, `stale`, `revoked`, or
     `not paired` for standalone-import devices from core v2's `finding_devices`), core v2
     `device-risk-v1` band chip and points column, `last_seen_at`, engine lock status
     (`up_to_date` / `locks_stale`), coverage badge, Finding counts by severity, and a
     **"Create pairing invite"** modal that displays the one-time pairing bundle and PDPL
     notice reminder.
2. **Per-device detail view (`/devices/{id}`):**
   - **Coverage & non-admin visibility panel:** Shows per engine (`host.windows`,
     `malware.files`, `network.windows`) which sources were read, the time span covered, and
     which detections are `not_visible` (e.g. `Security` log unreadable without admin rights
     → H1–H4, H8, H9, H13 shown in the dedicated "not visible" badge colour, never as clean),
     plus `queue_overflow_findings_dropped` if the offline queue ever overflowed.
   - **Risk panel (`device-risk-v1`, [core v2](core-v2.md) §3.5):** Total points, band,
     contribution table with primary recommended actions (`recommended-actions-v1`), and
     cross-engine corroboration explanation.
   - **Unified device timeline:** Shows Host, Malware and Network Findings for this
     `srv:<32 hex>` `device_ref` in chronological order, with severity, confidence, reason
     codes, primary recommended action, Sigma/YARA/blocklist attribution, `account_ref`
     (always `srv:<32 hex>` or `sid:S-1-5-*`), `path_ref` / location class, de-fanged
     indicator values where present, links to correlated Incidents, and a visible **"From a
     revoked device"** badge on Findings belonging to a revoked device (owner decision Q3,
     §11.1). Also shown on Incident detail timelines whenever an incident includes a Finding
     from a revoked device.
   - **Device actions:** Edit opaque `display_label`, **Revoke device token** (with
     confirmation), and, once a device is revoked, an optional **"Purge Findings since…"**
     control (`POST /devices/{id}/purge-findings`) requiring an explicit cutoff timestamp and
     reason.

### 7.3 Retention (reuses existing per-engine retention settings; owner decision Q2, §11.1)

No new retention environment variable is added. Instead, `data/scripts/retention.py` gains
`delete_expired_agent_findings(db)` which expires agent-submitted `sensor` Findings and
batches using the **existing per-engine retention settings**:

- `ETIS_HOST_RETENTION_DAYS` (default `30`, [host-engine-v1](host-engine-v1.md) §7) for
  `FindingRecord.engine_name == 'host.windows'`;
- `ETIS_MALWARE_RETENTION_DAYS` (default `30`, [malware-engine-v1](malware-engine-v1.md) §7)
  for `FindingRecord.engine_name == 'malware.files'`;
- `ETIS_NETWORK_RETENTION_DAYS` (default `30`,
  [network-windows-v1](network-windows-v1.md) §7) for
  `FindingRecord.engine_name == 'network.windows'`.

Clean-up rules:

1. For each of the three engines, selects `FindingRecord` rows with
   `source_kind == 'sensor'`, `engine_name == <engine>`, and `observed_at < cutoff` (or batch
   `received_at < cutoff`), and calls `_expire_findings` to delete those Findings (along with
   their `finding_devices` rows via cascade/explicit delete), write `findings_expired` events
   on affected Incidents, and remove orphaned hash-only indicators.
2. Extends `SCAN_DERIVED_SIGHTINGS` in `data/scripts/retention.py` to include
   `('sensor', 'host.windows')`, `('sensor', 'malware.files')` and
   `('sensor', 'network.windows')`, so hash-only indicators seen only in expired agent
   Findings are deleted, while indicators also present in public feeds (which carry plaintext
   `value`) or active Findings are preserved.
3. Deletes `agent_batches` rows whose `received_at` is older than the maximum of the three
   engine retention cutoffs and for which zero `FindingRecord` rows with
   `source_ref == f'agent_devices:{batch.device_id}:{batch.batch_id}'` remain, as well as
   expired `device_pairing_tokens`.
4. Revoked `devices` rows whose `revoked_at` is older than the maximum engine retention
   cutoff and that have zero remaining `agent_batches` and zero remaining `FindingRecord`
   rows are deleted.

### 7.4 Written employee notice for Egyptian PDPL (Law No. 151 of 2020)

> **Important note (to verify, §12 L1–L4):** The notice below is an engineering transparency
> template designed around data minimisation. The exact statutory requirements of the
> Egyptian Personal Data Protection Law (**Law No. 151 of 2020**, promulgated in the Official
> Gazette in July 2020) and its Executive Regulations — including the applicable legal basis
> in an employment context (explicit consent vs legitimate interest / workplace security
> policy), mandatory controller/Data Protection Officer (DPO) disclosures, language
> requirements, and licensing/notification obligations with the Personal Data Protection
> Center — have **not** been verified against the official Arabic statutory text or reviewed
> by legal counsel and are marked **to verify** (open question Q6, §11.2). This document
> makes no claim of legal compliance.

The agent prints this notice in both Arabic and English during `etis_agent pair` (and via
`etis_agent notice`), and pairing refuses to proceed unless the user explicitly acknowledges
`pdpl-notice-v1`:

#### Draft written notice — English (`pdpl-notice-v1`)

> **Employee Privacy and Data Processing Notice — ETIS Endpoint Agent (v1)**
>
> **1. Controller and Purpose:** `[Organization Name / DPO Contact Placeholder]` operates
> the Egyptian Threat Intelligence System (ETIS) on the internal company LAN solely for
> defensive cybersecurity monitoring (detecting malware, command-and-control traffic and
> host compromise indicators). ETIS is not used for employee productivity tracking,
> attendance monitoring or automated disciplinary decisions.
>
> **2. What Runs on Your PC:** The ETIS agent runs under your standard Windows user account
> without administrator privileges. When invoked, it reads locally available Windows event
> exports (`host.windows`), executable (`PE`) files in configured folders (`malware.files`),
> and local connection snapshots or exported DNS/firewall logs (`network.windows`).
>
> **3. What Is Sent to the Company LAN Server (Findings Only):**
> Only when a detection rule or model flags a security event does the agent send a structured
> `finding-v1` record over encrypted LAN HTTPS to the internal ETIS server. Each record
> contains:
> - Detection rule ID, severity, categorical confidence, reason codes and timestamps;
> - Keyed HMAC-SHA-256 pseudonyms for the device (`device_ref`), account (`account_ref`) and
>   flagged file path (`path_ref`), plus general file location class (e.g. `downloads`,
>   `program_files`); the server re-wraps device and account pseudonyms with a server-only
>   key (`srv:`) before storage;
> - SHA-256 hashes (`value=null`) of alerted remote IP addresses, alerted domains and
>   alerted executable files;
> - Coverage counts (how many records were checked and which log sources were visible).
>
> **4. What Never Leaves Your PC:**
> The agent **never** transmits or stores on the server:
> - Raw event logs, firewall logs or connection tables;
> - Your non-alerting browsing or DNS history;
> - File contents, document text, email bodies or script text;
> - Your plaintext Windows username, computer name, full file paths or command lines.
>
> **5. No Remote Control or Deletion:** The ETIS server cannot run commands on your PC,
> read files remotely, block connections, or quarantine/delete your files.
>
> **6. Retention and Your Controls:** Agent Findings are deleted from the LAN server
> according to the per-engine retention settings (`ETIS_HOST_RETENTION_DAYS`,
> `ETIS_MALWARE_RETENTION_DAYS`, `ETIS_NETWORK_RETENTION_DAYS`, each defaulting to 30 days).
> On your PC, you can view this notice (`python -m etis_agent notice`), inspect the local
> offline queue (`python -m etis_agent status`), disable optional user scheduling
> (`python -m etis_agent schedule --disable`), or uninstall the agent and wipe its local
> data at any time without administrator rights (`python -m etis_agent uninstall`). For
> privacy inquiries or requests under Egyptian Law No. 151 of 2020 (Personal Data Protection
> Law), contact `[DPO / Security Contact Placeholder]`.

#### مسودة إشعار الموظف المكتوب — العربية (`pdpl-notice-v1`)

> **إشعار خصوصية الموظفين ومعالجة البيانات — وكيل نظام ETIS على أجهزة Windows (الإصدار الأول v1)**
>
> **١. جهة التحكم والغرض من المعالجة:** تشغّل `[اسم المؤسسة / بيانات التواصل مع مسؤول حماية البيانات]`
> نظام معلومات التهديدات المصري (ETIS) داخل الشبكة المحلية للمؤسسة (LAN) حصرياً لأغراض الأمن
> السيبراني الدفاعي (رصد البرمجيات الخبيثة، واتصالات التحكم والسيطرة، ومؤشرات اختراق الأجهزة).
> لا يُستخدم النظام لمراقبة إنتاجية الموظفين أو الحضور أو اتخاذ قرارات تأديبية آلية.
>
> **٢. ما الذي يعمل على جهازك محلياً:** يعمل وكيل ETIS بصلاحيات حساب المستخدم العادي دون صلاحيات
> المسؤول (Administrator). عند تشغيله، يفحص محلياً ملفات سجلات أحداث Windows المتاحة
> (`host.windows`)، والملفات التنفيذية (`PE`) في المجلدات المحددة (`malware.files`)، ولقطات
> الاتصالات أو سجلات DNS وجدار الحماية المصدّرة (`network.windows`).
>
> **٣. ما الذي يُرسل إلى خادم الشبكة المحلية (النتائج Findings فقط):**
> فقط عند تطابق قاعدة كشف أمنية، يرسل الوكيل سجل نتيجة مهيكل (`finding-v1`) عبر اتصال HTTPS
> مشفر ومثبّت الشهادة إلى خادم ETIS الداخلي. يتضمن السجل فقط:
> - معرّف قاعدة الكشف، ومستوى الخطورة، ومستوى الثقة الفئوي، وأكواد الأسباب، والتوقيت؛
> - معرّفات مستعارة مشفرة بمفتاح (`HMAC-SHA-256`) للجهاز (`device_ref`) والحساب (`account_ref`)
>   ومسار الملف المرصود (`path_ref`)، مع فئة موقع الملف العامة (مثل `downloads` أو `program_files`)،
>   ويعيد الخادم تغليف معرّفات الجهاز والحساب بمفتاح خاص بالخادم (`srv:`) قبل أي تخزين؛
> - بصمات `SHA-256` فقط (`value=null`) لعناوين IP الخارجية أو النطاقات أو الملفات التنفيذية التي
>   أطلقت تنبيهاً؛
> - إحصاءات التغطية (عدد السجلات المفحوصة والمصادر المرئية أو غير المرئية).
>
> **٤. ما الذي لا يغادر جهازك أبداً:**
> لا يرسل الوكيل ولا يخزن الخادم إطلاقاً:
> - ملفات السجلات الخام أو جداول الاتصالات؛
> - سجل التصفح أو استعلامات DNS التي لم تطلق تنبيهاً؛
> - محتويات الملفات أو النصوص أو رسائل البريد أو نصوص البرمجيات النصية؛
> - اسم المستخدم أو اسم الجهاز أو المسارات الكاملة للملفات أو أسطر الأوامر بصورتها النصية.
>
> **٥. عدم وجود تحكم عن بُعد أو حذف:** لا يملك خادم ETIS أي قدرة على تنفيذ أوامر على جهازك، أو
> قراءة ملفاتك عن بُعد، أو حظر الاتصالات، أو حجز أو حذف أي ملف.
>
> **٦. مدة الاحتفاظ وحقوقك:** تُحذف نتائج الوكيل من خادم الشبكة المحلية وفق إعدادات الاحتفاظ الخاصة
> بكل محرك (`ETIS_HOST_RETENTION_DAYS` و`ETIS_MALWARE_RETENTION_DAYS`
> و`ETIS_NETWORK_RETENTION_DAYS`، وافتراضياً ٣٠ يوماً لكل منها). يمكنك في أي وقت دون صلاحيات
> المسؤول عرض هذا الإشعار (`python -m etis_agent notice`)، أو فحص طابور الانتظار المحلي
> (`python -m etis_agent status`)، أو إيقاف الجدولة الاختيارية
> (`python -m etis_agent schedule --disable`)، أو إزالة الوكيل ومسح بياناته المحلية بالكامل
> (`python -m etis_agent uninstall`). للاستفسارات المتعلقة بالخصوصية وفقاً لقانون حماية البيانات
> الشخصية المصري رقم ١٥١ لسنة ٢٠٢٠، يُرجى التواصل مع `[بيانات مسؤول حماية البيانات DPO]`.

---

## 8. Failure modes

| Failure mode | Agent behaviour | Server / Console behaviour |
| --- | --- | --- |
| **F1. Missing administrator rights for a log channel or file** (e.g. `Security.evtx`, `pfirewall.log` unreadable or absent) | Never prompts for UAC elevation; marks the source `unreadable_or_absent` and its rules `not_visible` in the batch coverage report; runs all remaining readable sources and engines. | Console shows affected rules in the distinct `not_visible` badge colour on `/devices/{id}`, never as "0 findings" or "clean". |
| **F2. LAN server unreachable, DNS failure, timeout or HTTP `5xx` / `429`** | Writes the sanitised `agent-batch-v1` payload to the local offline queue (`queue.db`), increments `attempts`, and exits cleanly (or backs off with jitter on scheduled runs). Never falls back to another host, port or plain HTTP. | If no batch or heartbeat arrives for > 24 h, `/devices` marks the device `stale` with its `last_seen_at` timestamp. |
| **F3. Server TLS certificate fingerprint mismatch (`tls_pin_mismatch`)** | Aborts the TLS connection before sending any HTTP headers (bearer token never transmitted); leaves batches in the local offline queue; reports `tls_pin_mismatch` to the user terminal. | No request reaches the application layer; operator must verify whether the server certificate changed or an active LAN MITM is present. |
| **F4. Offline queue reaches 10 MB / 100 batches / 5,000 Findings** | Evicts oldest lower-severity batches first (`info` → `low` → `medium` → oldest `high`), increments persistent `queue_overflow_batches_dropped` and `queue_overflow_findings_dropped` counters. | Next received batch updates `devices.last_coverage.queue_status` and surfaces a persistent `queue_overflow_dropped` warning badge on `/devices/{id}`. |
| **F5. Device token revoked by operator (`401 device_revoked`)** | Marks local pairing state `revoked`, stops sending further requests, and tells the user to re-pair if authorised. Does not delete queued batches unless the user runs `uninstall` or `clear-queue`. | Device row shows `status = 'revoked'`, `revoked_at`, rejects all `/agent/v1/*` requests with that token, keeps prior Findings marked `"from a revoked device"`, and allows optional manual operator purge after a chosen timestamp. |
| **F6. Network drop after server commits batch but before agent receives `200 OK`** | Agent retains the batch in `queue.db` and resends it with the same `batch_id` and `Finding.id`s on the next flush. | Server detects existing `(device_id, batch_id)` in `agent_batches`, inserts zero duplicate Findings, and returns `200 OK` with `duplicate_batch: true`. |
| **F7. Corrupt local queue SQLite file or DPAPI decryption failure** | Renames corrupt `queue.db` to `queue.corrupt.<timestamp>.db` (kept user-only locally) or resets unreadable secrets, refuses to transmit partial data, and reports `local_state_corrupt` (or `re_pair_required`). | Device appears `stale` until the user repairs or re-pairs. |
| **F8. Local engine artifact missing or lock mismatch on the endpoint** (e.g. YARA pack or network blocklist missing) | Engine reports its health reason (`rules_missing`, `blocklists_missing`, `model_missing`); available engines still run and their Findings are sent together with the degraded engine health in `coverage`. | Per-device page `/devices/{id}` displays the per-engine health state and `locks_stale` / `engine_degraded` badge. |
| **F9. Payload fails server privacy or schema gate (`422`)** | Agent removes the rejected batch from the retry loop, increments `local_rejected_batches_count`, and logs only the fixed error code (`device_ref_mismatch`, `device_ref_conflict`, `ref_prefix_invalid`, `plaintext_indicator_forbidden`, `disallowed_evidence_field`). | Server rolls back the batch transaction, stores nothing (no `hmac:` ref ever persisted), and logs the fixed error code without payload contents. |

---

## 9. Evaluation and verification gates (protocol & privacy, no model change)

FR-11 is a local execution wrapper and LAN transport/storage layer around the already
designed engines (`host.windows`, `malware.files`, `network.windows`). It adds **no new
detection rule, threshold or ML model**. Therefore, evaluation of FR-11 gates on protocol
correctness, engine parity, privacy containment and resource limits using invented fixtures:

1. **Engine output parity gate:** Running `host.windows`, `malware.files` and
   `network.windows` through the agent wrapper on the same invented EVTX, PE and network-log
   fixtures must produce the exact same `Finding` kinds, severities, confidences, reason
   codes, indicator hashes, ATT&CK technique IDs and `device_ref`/`account_ref`/`path_ref`
   pseudonyms as running each engine directly (with `device_ref` attached to malware Findings
   via `attach_device_ref` and wrapped to `srv:<32 hex>` by `record_findings`).
2. **Zero-leakage privacy gate:** Invented marker strings placed in computer names, Windows
   usernames, user SIDs, file paths, file names, file contents, command lines, PowerShell
   script blocks, non-alerting DNS queries, non-alerting firewall lines and local IP
   addresses must have **zero occurrences** (and zero unkeyed SHA-256 occurrences for
   usernames, computer names, paths and non-alerting destinations) in:
   - the offline queue (`queue.db`);
   - the HTTPS wire payload sent to `/agent/v1/*`;
   - any server database table (`devices`, `device_pairing_tokens`, `agent_batches`,
     `findings`, `finding_devices`, `indicators`, `indicator_sightings`, `incidents`,
     `incident_events`), where all stored device and account refs must also be `srv:<32 hex>`
     (or `sid:S-1-5-18/-19/-20`) with **zero stored `hmac:` device or account refs**;
   - `/devices` and `/incidents` API responses; and
   - agent and server logs.
3. **Transport & pinning gate:** Zero outbound connections to any non-LAN address; immediate
   abort before sending HTTP headers when the server certificate DER SHA-256 matches neither
   `primary_cert_sha256` nor `next_cert_sha256`; zero redirects followed.
4. **Non-admin & no-persistence gate:** The agent test suite runs with privileged APIs and
   system locations mocked/blocked (`wevtutil sl`, `netsh`, `sc.exe`, `HKLM`, UAC elevation);
   default run creates zero scheduled tasks or registry entries.

---

## 10. Step plan with tests for each step

Each implementation step is a small, reviewable commit. Every step runs targeted pytest for
the touched modules (and the `/analyze` verdict parity gate, database initialisation,
frontend build and lint before PR merge). No step touches `evaluation/`, `data/external/` or
any `FREEZE.json` file.

| Step | Commit message | Scope | Tests for this step |
| --- | --- | --- | --- |
| 0 | `docs: Windows agent and LAN server design v1` | This design document (`docs/design/windows-agent-lan-v1.md`), aligned with [core v2](core-v2.md) §3.6. | Review against `network-windows-v1.md`, `browser-extension-v1.md` and `core-v2.md` conventions; no code changes. |
| 1 | `feat: migration for agent devices, pairing invites and batches` | Alembic migration `010_agent_devices` (or next free revision after core v2's `009_finding_devices`) and SQLAlchemy models `Device` (`device_ref` storing `srv:<32 hex>`), `DevicePairingToken`, `AgentBatch` in `backend/app/models/agent_device.py`. Ensures `ETIS_SERVER_REF_KEY` is generated in `scripts/initialize.py` without overwriting an existing key. | Migration tests (`test_agent_devices_migration.py`): empty DB → head, upgrade from `009` with existing rows → head, idempotent re-run, downgrade, and column-by-column check that existing tables are untouched. |
| 2 | `feat: agent batch schemas, evidence allowlist and privacy validator` | Pydantic strict schemas (`AgentPairRequest`, `AgentBatchRequest`, `AgentHeartbeatRequest`, `AgentCoverage`) and server-side validator enforcing `^hmac:[0-9a-f]{32}$` on the wire, rejecting `srv:` on the wire (`422 ref_prefix_invalid`), checking `wrap_ref(incoming_hmac, "device") == device.device_ref` (`srv:`) via `hmac.compare_digest` (`422 device_ref_mismatch`), enforcing `indicator.value is None`, and checking per-engine `evidence.details` key/format allowlists. | `test_agent_schemas.py`: valid batches for `host.windows`, `malware.files` and `network.windows` pass; wrapped `hmac:` matching stored `srv:` passes and mismatched `hmac:` fails with `422 device_ref_mismatch`; incoming `srv:` on the wire fails with `422 ref_prefix_invalid`; any non-null `indicator.value`, unknown `evidence.details` key, or raw path/username/hostname string is rejected with `422`. |
| 3 | `feat: LAN server agent pairing, batch ingestion and device management API` | Routers `/agent/v1/pair` (wraps `hmac:` to `srv:`, stores `srv:`, never echoes `device_ref`), `/agent/v1/batches`, `/agent/v1/heartbeat`, `/agent/v1/unpair` and operator endpoints `/devices`, `/devices/{id}`, `/devices/pairing-invites`, `/devices/{id}/revoke`, `/devices/{id}/purge-findings` (exposing/accepting `srv:` refs only). Calls `record_findings` (`source.kind = 'sensor'`, which wraps device and account refs to `srv:` and writes `finding_devices`). | `test_agent_server_api.py`: one-use pairing code exchange stores `srv:` and omits `device_ref` from response; zero `hmac:` device/account refs stored in DB; revoked token returns `401 device_revoked` while existing Findings remain marked `from_revoked_device: true`; optional manual `purge-findings` removes only Findings on/after `since` and refuses on active devices; idempotent `(device_id, batch_id)` retry; cross-engine/cross-device correlation; isolation between `agent_token` and `X-API-Key`. |
| 4 | `feat: retention for agent batches, sensor findings and revoked devices` | Extend `data/scripts/retention.py` with `delete_expired_agent_findings` reusing `ETIS_HOST_RETENTION_DAYS`, `ETIS_MALWARE_RETENTION_DAYS` and `ETIS_NETWORK_RETENTION_DAYS` (no new setting) and sensor-sighting orphan indicator clean-up. | `test_agent_retention.py`: per-engine cutoffs expire each engine's `sensor` Findings and orphan hash-only indicators independently; `agent_batches` and revoked `devices` are deleted only once no Findings remain; `findings_expired` events are written on incidents; indicators shared with active feeds or non-expired Findings are preserved. |
| 5 | `feat: windows agent local runner, non-admin coverage and privacy sanitizer` | User-space agent runner (`backend/app/agent/runner.py`) that invokes `host.windows`, `malware.files` and `network.windows` on local user-readable inputs, uses `local_device_name()` and `attach_device_ref()` from `app/core/device_names.py`, converts `PermissionError` / missing sources to `not_visible` coverage, and runs the local marker/schema sanitizer. | `test_agent_runner.py`: parity test proving agent-wrapped engine outputs match direct engine outputs on invented EVTX, PE and network fixtures; unreadable `Security.evtx` / `pfirewall.log` produce `not_visible` coverage without crash or elevation; marker-string privacy test across all three engines. |
| 6 | `feat: windows agent bounded offline queue with severity-preserving overflow` | Local SQLite queue (`backend/app/agent/queue.py`) with 10 MB / 100-batch / 5,000-Finding limits, 14-day local expiry, severity-ordered eviction (`info` → `low` → `medium` → oldest `high`), and persistent `queue_overflow_*` counters. | `test_agent_queue.py`: FIFO enqueue/dequeue, byte and count limit enforcement, severity-priority eviction order, overflow counter persistence into the next batch's coverage report, and corrupt-queue recovery. |
| 7 | `feat: windows agent pinned-cert LAN HTTPS client, CLI, notice and uninstall` | Standard-library `ssl` client with LAN locality check (`locality(ip) == 'local'`), DER leaf-certificate SHA-256 pinning (`primary_cert_sha256` and optional `next_cert_sha256`) before HTTP write, no redirects/proxies, bilingual PDPL 151/2020 notice prompt (`pdpl-notice-v1`), local secret storage, opt-in user schedule command and `uninstall` command. | `test_agent_transport_and_cli.py`: local loopback TLS server tests verifying `primary` and `next` pin match succeeds, 1-bit pin mismatch aborts before sending `Authorization` header, non-LAN IP targets are refused before socket connect, redirects are refused, `pair` requires notice acknowledgement, default run creates zero tasks/registry keys, and `uninstall` wipes the agent state directory. |
| 8 | `feat: devices console tab and proxy routes` | Allowlist `/api/devices/*` in `etis-frontend/proxy-routes.mjs` (never `/agent/v1/*`), and add/extend the bilingual **"Devices (LAN)"** console tab and per-device detail page (`/devices`, `/devices/{id}`) in Arabic and English, displaying `srv:` refs only, `"From a revoked device"` badges, manual purge modal, and de-fanged `<IndicatorValue />`. | `test_proxy_routes.py`, frontend build (`npm run build`) and `oxlint`: verify `/api/devices/*` works with session/Origin checks, `/api/agent/*` is refused (`404`), indicators use `IndicatorValue`, and every new Arabic/English i18n key is present. |
| 9 | `docs: windows agent and LAN server implementation notes` | Update `README.md`, `LOCAL-IMPLEMENTATION.md`, `docs/api-v2.md`, optional IT admin log-export policy instructions and operator certificate/pairing instructions. | Targeted regression check on agent/device tests and `/analyze` parity gate. |

---

## 11. Owner decisions and open questions

### 11.1 Owner decisions (27 November 2026)

| # | Decision | Where applied |
| --- | --- | --- |
| Q1 | **Server re-wrap of device and account refs (as in [core v2](core-v2.md) §3.2, §3.6):** The endpoint computes and sends `hmac:<32 hex>` with `ETIS_HOST_PSEUDONYM_KEY` (using `local_device_name()` and `attach_device_ref()` from `app/core/device_names.py`). The server holds a separate `ETIS_SERVER_REF_KEY` (generated by `scripts/initialize.py`, never overwritten, never sent to an agent) and wraps `device_ref` / `host_ref` (`purpose="device"`) and `account_ref` (`purpose="account"`, keeping well-known `sid:S-1-5-18/-19/-20` unchanged) into `srv:<32 hex>` before any storage — at pairing for `devices.device_ref` (not echoed in the pairing response) and in `record_findings` for Findings and `finding_devices`. The batch check compares `wrap_ref(incoming_hmac, "device")` against the stored `srv:` `devices.device_ref`. Console and operator APIs show and accept `srv:` refs only. | §0, §1.1, §1.3, §2.2 (A4, A5), §3, §4.1, §5.1–5.3, §7.1–7.2, §9, §10 (steps 1–3, 5, 8) |
| Q2 | **Reuse existing per-engine retention settings (no `ETIS_AGENT_RETENTION_DAYS`):** Agent-submitted `sensor` Findings expire under the existing per-engine settings (`ETIS_HOST_RETENTION_DAYS`, `ETIS_MALWARE_RETENTION_DAYS`, `ETIS_NETWORK_RETENTION_DAYS`, all defaulting to 30 days). No new retention variable is added. | §7.3, §7.4, §10 (step 4) |
| Q3 | **Keep a revoked device's Findings and mark them `"from a revoked device"`, with an optional, never-automatic purge after a chosen time:** Revoking a device keeps its existing Findings in the database and in open Incidents by default and flags them with `from_revoked_device: true` (`"From a revoked device"` badge in the console). A separate operator endpoint (`POST /devices/{id}/purge-findings` with `{since, reason}`) allows manually purging Findings and batches from a revoked device on or after a chosen timestamp; it never runs automatically. | §2.2 (A4), §4.1, §5.3, §7.2, §8 (F5), §10 (steps 3, 8) |
| Q4 | **Document admin-run log export as an optional company IT policy; the agent itself never gets admin:** An organisation's IT administrator may optionally run their own separate administrative task (outside ETIS) to export `Security.evtx`, `DNS-Client.evtx` and `pfirewall.log` into a folder readable by the standard user. The ETIS agent never holds or requests administrator rights. | §1.2, §10 (step 9) |
| Q5 | **Pin the leaf certificate DER SHA-256 with `primary` + `next` pins:** Use standard-library `ssock.getpeercert(binary_form=True)` SHA-256 pinning with `primary_cert_sha256` and optional `next_cert_sha256` overlap pins for certificate rotation. | §0, §2.2 (A1), §4.1, §4.2, §5.3, §9, §10 (step 7) |
| — | **Alembic migration number moves to `010_agent_devices`:** Because [core v2](core-v2.md) takes `009_finding_devices`, the agent migration is `010_agent_devices` (or next free number), with its upgrade test starting from `009`. | §7.1, §10 (step 1) |

### 11.2 Open questions

- **Q6. Legal review of the PDPL 151/2020 employee notice:** Does the organisation's
  deployment rely on employee written acknowledgement under workplace security policy or
  explicit consent under Egyptian Law No. 151 of 2020, and what DPO / Personal Data
  Protection Center details must be filled into the §7.4 template after legal review?

---

## 12. To verify (before the step that depends on it)

| # | Item to verify | Primary source to read | Needed by step |
| --- | --- | --- | --- |
| W1 | Default Windows 10/11 read permissions (SDDL / ACLs) for standard users vs `Event Log Readers` vs Administrators on `Security`, `System`, `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-Windows Defender/Operational`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-DNS-Client/Operational` and `Microsoft-Windows-Sysmon/Operational`. | Microsoft Learn: *Event Logging Security* / *Channel Access Strings* (`learn.microsoft.com/en-us/windows/win32/wes/event-log-security`) and local `wevtutil gl <channel>` read-only output on the project PC | 5, 9 |
| W2 | Default file ACLs on `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log` for a standard Windows user. | Microsoft Learn: *Configure Windows Firewall logging* (`learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging`) | 5, 9 |
| W3 | Whether `GetExtendedTcpTable` (`iphlpapi.dll`, `TCP_TABLE_OWNER_PID_ALL`) succeeds for a non-elevated standard Windows user and which process inspection calls (`OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` / `QueryFullProcessImageNameW`) succeed across user boundaries without admin rights. | Microsoft Learn: `GetExtendedTcpTable` (`learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable`) and *Process Security and Access Rights* (`learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights`) | 5 |
| W4 | Standard user read access across `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%SystemRoot%\System32` and `%LOCALAPPDATA%\Programs` on Windows 11, and behavior of shared-read file opens (`FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE`) on locked binaries. | Microsoft Learn: `CreateFileW` (`learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew`) | 5 |
| W5 | Whether a standard user on Windows 10/11 can create and delete their own user-level scheduled task (`schtasks.exe /Create /RU <current_user> /RL LIMITED`) without administrator elevation, or whether per-user opt-in scheduling must use `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or a user startup shortcut. | Microsoft Learn: `schtasks create` (`learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create`) and *Run and RunOnce Registry Keys* (`learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys`) | 7 |
| S1 | Python 3.12 `ssl.SSLContext` behavior when connecting to a self-signed server certificate with `CERT_NONE` vs custom CA vs `getpeercert(binary_form=True)`: verify that the TLS handshake completes, authenticates the server's possession of the private key corresponding to the leaf certificate, and allows checking `sha256(der_cert)` before writing any HTTP request bytes on the wrapped socket. | Python 3.12 official documentation: `ssl` — *TLS/SSL wrapper for socket objects* (`docs.python.org/3.12/library/ssl.html`) and RFC 8446 (TLS 1.3 handshake transcript authentication) | 7 |
| S2 | Connecting by verified LAN IP while passing SNI / hostname, and guaranteeing that `http.client.HTTPSConnection` (or a custom `ssl.SSLSocket` wrapper) never sends HTTP headers before the custom certificate fingerprint check runs. | Python 3.12 official documentation: `http.client` (`docs.python.org/3.12/library/http.client.html`) and `ssl.SSLContext.wrap_socket` | 7 |
| S3 | Windows DPAPI `CryptProtectData` and `CryptUnprotectData` in `Crypt32.dll` via `ctypes` (`DATA_BLOB`, `CRYPTPROTECT_UI_FORBIDDEN = 0x1`, `LocalFree`): exact structure layout on 64-bit Windows and threat boundary (protects against other Windows accounts and offline disk inspection, not same-user processes). | Microsoft Learn: `CryptProtectData` (`learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata`) | 7 |
| S4 | Restricting `%LOCALAPPDATA%\ETIS-Agent\` directory permissions on Windows so that only the current user SID and `SYSTEM`/`Administrators` have access (whether inherited `%LOCALAPPDATA%` ACLs already guarantee this on Windows 11, and how to verify/enforce it via Win32 or `icacls`). | Microsoft Learn: *DACLs and ACEs* (`learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces`) and `icacls` (`learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls`) | 6, 7 |
| S5 | FastAPI / Uvicorn TLS configuration and request-body size limiting for `/agent/v1/*`, plus ensuring access logs and middleware never log `Authorization` headers, pairing codes or request bodies. | FastAPI / Uvicorn official documentation (`uvicorn.org/settings/`) and local inspection of `backend/app/main.py` | 3, 7 |
| L1 | Exact articles and obligations of the Egyptian Personal Data Protection Law (**Law No. 151 of 2020**, published in the Official Gazette *Al-Jarida Al-Rasmiya*, Issue 28 bis (K), 15 July 2020) and its Executive Regulations regarding workplace cybersecurity monitoring, pseudonymised technical identifiers, and legal basis (consent vs legitimate interest / statutory duty). | Official Arabic text of Law No. 151 of 2020 in the Egyptian Official Gazette and review by qualified Egyptian legal counsel | 7, 9 |
| L2 | Data Subject rights and mandatory controller disclosures required in a written notice under Law No. 151 of 2020 (controller identity, purpose, retention, DPO contact, right to access/withdraw/complain). | Official Arabic text of Law No. 151 of 2020 | 7, 9 |
| L3 | Data Protection Officer (DPO) appointment and Personal Data Protection Center licensing/permit requirements for an internal company LAN deployment under Law No. 151 of 2020. | Official Arabic text of Law No. 151 of 2020 and Executive Regulations | 9 |
| L4 | Any sector-specific retention or incident-reporting rules applicable to the deploying organisation in Egypt (e.g. NTRA / EG-CERT / CBE frameworks, if applicable). | Official sector regulator publications, only if applicable to the deploying organisation | 9 |

---

## Sources

Read locally in this repository (**verified** facts on existing ETIS schemas, pseudonyms,
engines, retention and migrations):

- `CLAUDE.md`, `README.md`, `LOCAL-IMPLEMENTATION.md`, `docs/api-v2.md`, `docs/engine-authors.md`
- [Core v1 design](core-v1.md) (`finding-v1`, indicator store, correlation, ATT&CK v20.0)
- [Core v2 design](core-v2.md) (§3.2, §3.5, §3.6, §4.4: `ETIS_SERVER_REF_KEY`, `srv:` re-wrapping, `app/core/device_names.py`, `009_finding_devices`, `device-risk-v1`, `IndicatorValue`)
- [Host engine v1 design](host-engine-v1.md) (`host.windows`, `ETIS_HOST_PSEUDONYM_KEY`, coverage)
- [Malware engine v1 design](malware-engine-v1.md) (`malware.files`, `ETIS_MALWARE_PSEUDONYM_KEY`, location classes)
- [Network-lite Windows engine v1 design](network-windows-v1.md) (`network.windows`, `device_ref`, W1–W13)
- [Local browser extension v1 design](browser-extension-v1.md) (pairing, local transport boundary, style)
- `backend/app/core/findings.py` (`Finding`, `SourceKind = Literal['scan', 'feed', 'analyst', 'community', 'sensor', 'import']`)
- `backend/app/engines/host/pseudonyms.py` (`KEY_ENV = 'ETIS_HOST_PSEUDONYM_KEY'`, `Pseudonymizer.host_ref`, `Pseudonymizer.account_ref`, `locality`)
- `backend/app/services/findings.py` (`record_findings`, incident correlation and stoplist exclusions)
- `data/scripts/retention.py` (`_expire_findings`, `SCAN_DERIVED_SIGHTINGS`, `delete_expired_malware`, `delete_expired_network_windows`)
- `scripts/initialize.py` (`PSEUDONYM_KEYS`) and `etis-frontend/server.mjs`

Unopened official reading sources, all **to verify** before the step that depends on them
(§12):

- Microsoft Learn — Event Logging Security: `https://learn.microsoft.com/en-us/windows/win32/wes/event-log-security`
- Microsoft Learn — Process Security and Access Rights: `https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights`
- Microsoft Learn — `CryptProtectData` (DPAPI): `https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata`
- Microsoft Learn — `schtasks create`: `https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create`
- Microsoft Learn — `icacls`: `https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls`
- Python 3.12 Documentation — `ssl` module: `https://docs.python.org/3.12/library/ssl.html`
- Egyptian Official Gazette (*Al-Jarida Al-Rasmiya*) — Personal Data Protection Law No. 151 of 2020 (Issue 28 bis (K), 15 July 2020)
