# Docker Compose LAN server deployment v1 — design

Status: **design only** (27 November 2026), branch `feat/docker-lan`. No `Dockerfile`,
`compose.yaml`, `.dockerignore`, script or code change accompanies this document. A fact is
marked **verified** only when it was read directly in this repository's existing files
(`Dockerfile`, `etis-frontend/Dockerfile`, `compose.yaml`, `.dockerignore`, `.env.example`,
`SETUP.md`, `scripts/initialize.py`); every fact about Docker Engine, Docker Compose,
PostgreSQL 16, Node/Nginx TLS reverse-proxy behavior, Linux container capabilities and
read-only root filesystem mounts is marked **to verify**, with the official documentation
page to read, and is listed again in §10. No number in this document comes from a
measurement.

This design specifies how to run the ETIS LAN server (supporting the SOC console of
[core v1](core-v1.md) / [core v2](core-v2.md) and the Windows endpoint agent of
[windows-agent-lan-v1](windows-agent-lan-v1.md), FR-11) in Docker Compose with PostgreSQL,
the FastAPI backend (`api` and `worker`), and the built React console (`web`) behind a
single LAN-only HTTPS reverse proxy.

---

## 0. Current repository baseline (verified) and what must change

Read in this repository on 27 November 2026 (**verified**):

| File (today) | Current behaviour (**verified**) | Gap for LAN server v1 |
| --- | --- | --- |
| `Dockerfile` | `FROM python:3.12-slim` (unpinned floating tag); copies `ml/models` and `ml/data/tokenizer.pkl` into the image; runs as `root` (no `USER`); runs `uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log`. | Must pin the base image by exact version and `@sha256:` digest, **never** copy `ml/models` or `ml/data` into the image, create and switch to a non-root user, and support a read-only root filesystem. |
| `etis-frontend/Dockerfile` | `FROM node:24-slim` (unpinned floating tag); multi-stage build copies `dist/`, `server.mjs` and `proxy-routes.mjs`; runs as `root` (no `USER`); has no `HEALTHCHECK`. | Must pin `node:22.12.0-bookworm-slim` (or pinned LTS) by `@sha256:` digest, run as a non-root user, support a read-only root filesystem, and define a healthcheck. |
| `.dockerignore` | Excludes only `.git`, `.env`, `.venv`, `var`, `etis-frontend/node_modules`, `data/private` and `evaluation/review-evidence`. | Must also exclude `ml/models/`, `ml/data/`, `data/models/`, `data/external/`, `data/raw/`, `data/processed/`, `evaluation/`, `release-artifacts/`, `colab-bundle/`, `.env.*`, `*.db`, `*.sqlite*`, `*.log`, `*.pem`, `*.key`, `*.crt`, `backend/tests/` and `docs/`. |
| `compose.yaml` | Uses floating `postgres:16`; exposes `127.0.0.1:5173:5173` on `web`; passes only `DATABASE_URL`, `ETIS_API_KEY` and `ETIS_TEXT_MODEL`; `migrate` runs `scripts/initialize.py` (which tries to edit `/app/.env`); no TLS reverse proxy; no `read_only: true`, `user:`, `cap_drop` or `no-new-privileges`; no healthcheck on `web` or `worker`. | Must place `api` and `web` behind one LAN-only HTTPS reverse proxy, pass all runtime secrets from `.env` without writing `.env` inside a container, mount model files `:ro` at runtime, enforce non-root + `read_only: true` + healthchecks on every service, and keep PostgreSQL on an internal-only network with a named volume. |

---

## 1. Constraints

| Constraint | How this design keeps it |
| --- | --- |
| **LAN only, single entry point** | Only the reverse proxy publishes a host port, bound to the server's literal RFC 1918 LAN IP (`${ETIS_LAN_BIND_IP}:8443:8443`, or `127.0.0.1:8443:8443` for local testing). PostgreSQL (`database`), FastAPI (`api`), `migrate`, `worker` and `web` publish **zero** host ports. |
| **Secrets from `.env` at runtime only** | All secrets (`ETIS_DB_PASSWORD`, `ETIS_API_KEY`, `ETIS_HOST_PSEUDONYM_KEY`, `ETIS_MALWARE_PSEUDONYM_KEY`, `ETIS_SERVER_REF_KEY`, `ETIS_STIX_NAMESPACE`) live in ignored `.env` on the host and are injected as runtime environment variables (`env_file` / `environment`). TLS key material lives in ignored `var/certs/` on the host and is bind-mounted `:ro`. No secret is ever passed via `ARG`, `ENV` in a `Dockerfile`, or `COPY`. |
| **Pinned image versions** | Every `FROM` in Dockerfiles and `image:` in `compose.yaml` is pinned to an exact version tag and SHA-256 manifest digest (`<name>:<version>@sha256:<64 hex>`). Floating tags (`latest`, `3.12-slim`, `16`) are rejected by a static test (§8). |
| **What never enters an image** | `.dockerignore` and the Dockerfiles exclude `.env*`, all ML models (`ml/models/`, `data/models/`, `release-artifacts/`), all datasets (`ml/data/`, `data/external/`, `data/raw/`, `data/processed/`, `data/private/`), `evaluation/`, `var/`, certificates, databases and tests (§3). Required frozen inference artifacts are bind-mounted read-only (`:ro`) at runtime. |
| **Non-root and read-only rootfs** | Every long-running container runs as an unprivileged UID/GID (`USER 10001:10001` for Python services, non-root for Node/proxy/PostgreSQL), with `read_only: true`, `security_opt: ["no-new-privileges:true"]`, `cap_drop: ["ALL"]` (subject to PostgreSQL entrypoint verification, §10 D3), and bounded `noexec,nosuid,nodev` `tmpfs` mounts for `/tmp`. |
| **Healthcheck per service & named DB volume** | Every long-running service (`database`, `api`, `web`, `reverse-proxy`, `worker`) defines a container-local healthcheck. PostgreSQL state persists in the named volume `etis_pgdata`. |
| **Verdicts, engines and schemas untouched** | Containerisation changes no detection logic, model, threshold or API payload. |

---

## 2. Service architecture and network topology

### 2.1 Text topology diagram

```text
Company LAN (RFC 1918, e.g. 192.168.1.0/24)
  |
  |  HTTPS only on ${ETIS_LAN_BIND_IP}:8443 (TLS 1.3 / 1.2, pinned server leaf cert)
  v
+-----------------------------------------------------------------------------------+
| HOST MACHINE (Docker Compose)                                                     |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | reverse-proxy (Pinned TLS proxy, non-root, read_only: true)                 |  |
|  |  - Attached to etis_lan_net (bridge, non-internal) & etis_edge_net (internal)|  |
|  |  - Binds ONLY ${ETIS_LAN_BIND_IP}:8443:8443                                 |  |
|  |  - Mounts ./var/certs/lan-server.crt & lan-server.key (:ro)                 |  |
|  |  - Routes /agent/v1/*  ---> http://api:8000/agent/v1/* (Bearer token only,  |  |
|  |                             max body 512 KB, access log off)                |  |
|  |  - Routes / and /api/* ---> http://web:5173 (Console SPA + session proxy)   |  |
|  +-------------------+-------------------------------------+-------------------+  |
|                      | (etis_edge_net, internal: true)     |                      |
|                      v                                     v                      |
|  +-----------------------------------+   +-------------------------------------+  |
|  | web (etis-frontend/server.mjs)    |   | api (FastAPI / Uvicorn)             |  |
|  |  - Non-root, read_only: true      |   |  - Non-root (10001), read_only: true|  |
|  |  - Serves built dist/             |   |  - Mounts frozen models (:ro)       |  |
|  |  - Holds ETIS_API_KEY in memory   |-->|  - Mounts pinned locks/lists (:ro)  |  |
|  |  - Issues Secure HttpOnly cookie  |   |  - Zero host ports published        |  |
|  |  - Forwards allowlisted /api/*    |   +-----------------+-------------------+  |
|  +-----------------------------------+                     |                      |
|                                                            | (etis_db_net,        |
|  +-----------------------------------+                     |  internal: true,     |
|  | migrate (one-shot) & worker       |---------------------+  no external egress) |
|  |  - Non-root (10001), read_only    |                     |                      |
|  |  - migrate: alembic upgrade head  |                     v                      |
|  |    + idempotent DB seeding        |   +-------------------------------------+  |
|  |  - worker: retention (& optional  |   | database (PostgreSQL 16, pinned)    |  |
|  |    feed refresh when enabled)     |   |  - Non-root postgres user           |  |
|  +-----------------------------------+   |  - Named volume: etis_pgdata        |  |
|                                          |  - Zero host ports published        |  |
|                                          +-------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

### 2.2 Services

| Service | Image / Build | User (UID:GID) | Root filesystem | Volumes / Mounts | Published host ports | Healthcheck |
| --- | --- | --- | --- | --- | --- | --- |
| `database` | `postgres:16.<patch>-bookworm@sha256:<digest>` (**to verify**, §10 D1) | `postgres` (`999:999`, **to verify**, §10 D3) | `read_only: true` + `tmpfs` for `/tmp` and `/var/run/postgresql` (**to verify**, §10 D3) | Named volume `etis_pgdata:/var/lib/postgresql/data` | **None** | `["CMD-SHELL", "pg_isready -U etis -d etis -h 127.0.0.1"]` (`interval: 10s`, `timeout: 5s`, `retries: 5`) |
| `migrate` | Built from root `Dockerfile` (`etis-backend:lan-v1`) | `10001:10001` | `read_only: true` + `tmpfs` `/tmp` | Optional `./data/external/attack:/app/data/external/attack:ro` (for ATT&CK v20.0 catalogue seeding) | **None** | One-shot job (`service_completed_successfully`); exits `0` after `alembic upgrade head` and seeding |
| `api` | Same `etis-backend:lan-v1` image | `10001:10001` | `read_only: true` + `tmpfs` `/tmp` | Read-only bind mounts (§3.2) for frozen deployed models and optional pinned offline lists | **None** | `["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"]` (`interval: 15s`, `timeout: 5s`, `retries: 3`) |
| `worker` | Same `etis-backend:lan-v1` image | `10001:10001` | `read_only: true` + `tmpfs` `/tmp` | None (writes heartbeat file to `/tmp/worker_heartbeat`) | **None** | `["CMD", "python", "-c", "import os,time,sys; sys.exit(0 if time.time()-os.path.getmtime('/tmp/worker_heartbeat')<7200 else 1)"]` (`interval: 60s`, `timeout: 5s`, `retries: 3`) |
| `web` | Built from `etis-frontend/Dockerfile` (`etis-web:lan-v1`) | `10002:10002` (or `node` `1000:1000`) | `read_only: true` + `tmpfs` `/tmp` | None (`dist/` is static compiled UI code built during image build) | **None** | `["CMD", "node", "-e", "fetch('http://127.0.0.1:5173/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]` (`interval: 15s`, `timeout: 5s`, `retries: 3`) |
| `reverse-proxy` | `nginxinc/nginx-unprivileged:1.27.4-bookworm@sha256:TO_VERIFY_nginx_unprivileged` (**to verify**, §10 D1, D4) | `101:101` (unprivileged) | `read_only: true` + `tmpfs` `/tmp`, `/var/cache/nginx`, `/var/run` (**to verify**, §10 D4) | `./var/certs/lan-server.crt:/etc/nginx/certs/server.crt:ro`, `./var/certs/lan-server.key:/etc/nginx/certs/server.key:ro`, `./docker/nginx-lan.conf:/etc/nginx/conf.d/default.conf:ro` | **`${ETIS_LAN_BIND_IP}:8443:8443`** (via non-internal `etis_lan_net`, attached only to `reverse-proxy`) | `["CMD-SHELL", "test -s /tmp/nginx.pid && kill -0 $(cat /tmp/nginx.pid)"]` (`interval: 15s`, `timeout: 5s`, `retries: 3`) |

### 2.3 Reverse proxy routing and LAN binding

1. **Host IP binding (`ETIS_LAN_BIND_IP`):**
   - `compose.yaml` binds the reverse proxy port as `"${ETIS_LAN_BIND_IP:?Set ETIS_LAN_BIND_IP in .env}:8443:8443"`.
   - The host preparation script (`scripts/init_lan_env.py`, §4.1) validates `ETIS_LAN_BIND_IP` with `app.engines.host.pseudonyms.locality(ip)` so that only a private LAN address (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, IPv6 ULA `fc00::/7`, or `127.0.0.1` for local testing) is accepted; `0.0.0.0` and public IP addresses are refused.
2. **Path routing behind the single reverse proxy (`https://<ETIS_LAN_BIND_IP>:8443`):**
   - **`/agent/v1/*`** (`POST /agent/v1/pair`, `/agent/v1/batches`, `/agent/v1/heartbeat`, `/agent/v1/unpair` from [windows-agent-lan-v1](windows-agent-lan-v1.md) §5.1):
     - Proxied directly to `http://api:8000/agent/v1/*`.
     - Forwards the agent's `Authorization: Bearer <agent_token>` header; **never** attaches `X-API-Key` or session cookies.
     - Enforces `client_max_body_size 512k;`, `access_log off;`, and `Cache-Control: no-store`.
   - **`/` and `/api/*`** (SOC console and operator API):
     - Proxied to `http://web:5173`.
     - `etis-frontend/server.mjs` validates `Host` against `ETIS_ALLOWED_HOSTS` (configured to `127.0.0.1,${ETIS_LAN_BIND_IP}`), validates `Origin`, issues `HttpOnly; SameSite=Strict; Secure` (`ETIS_SECURE_COOKIE=true`) session cookies, enforces rate limits and the 32 KB body cap, and forwards only allowlisted `/api/*` routes (from `etis-frontend/proxy-routes.mjs`) to `http://api:8000` with `X-API-Key`.
     - **Known limitation (per-IP rate limiting behind `reverse-proxy`):** `etis-frontend/server.mjs` keys its per-IP rate limiter on `req.socket.remoteAddress`, which inside `etis_edge_net` is always the `reverse-proxy` container's IP address for every LAN client. Consequently, all LAN console users share a single 60 requests/minute per-IP bucket at `web`; per-session rate limits (`session:<cookie>`) and backend `/analyze` rate limits (`X-ETIS-Session`) still apply independently per session.
   - **Never exposed through the LAN reverse proxy:**
     - `/extension/v1/pair` and `/extension/v1/check` ([browser-extension-v1](browser-extension-v1.md) §2.2: those are strictly `http://127.0.0.1:8000` loopback routes for a local desktop browser extension and are blocked at the LAN reverse proxy with `404`).

---

## 3. What never goes into an image vs what is mounted at runtime

### 3.1 Forbidden in every Docker image (enforced by `.dockerignore` and static tests)

| Category | Paths excluded by `.dockerignore` and absent from `Dockerfile` | Reason |
| --- | --- | --- |
| **Secrets & certificates** | `.env`, `.env.*`, `var/certs/`, `*.pem`, `*.key`, `*.crt`, `*.p12` | Secrets baked into an image layer survive in `docker history` and image registries even if deleted in a later layer. |
| **Trained models & weights** | `ml/models/*.joblib`, `ml/models/*.keras`, `ml/models/*.h5`, `ml/models/*.pkl`, `ml/data/*`, `data/models/`, `release-artifacts/`, `colab-bundle/` | Models are large binary artifacts subject to separate freeze/lock rules; keeping them out of the image lets the image remain code-only and reproducible. |
| **Datasets, rule packs & external feeds** | `data/external/` (ATT&CK STIX, Sigma, YARA, EMBER2024, EVTX samples, network blocklists), `data/raw/`, `data/processed/`, `data/private/` | Governed by third-party data licences (`docs/data-licences.md`, e.g. GPL-3.0, DRL-1.1, abuse.ch terms) and `.gitignore`; must never be redistributed inside a container image. |
| **Evaluation & local results** | `evaluation/` (reports, `FREEZE.json`, `targets.json`, `local-results/`, `review-evidence/`) | Evaluation evidence and sealed/frozen rules are not runtime server code. |
| **Local databases, logs & dev folders** | `var/`, `*.db`, `*.sqlite*`, `*.log`, `.git/`, `.venv*/`, `.pytest_cache/`, `node_modules/`, `backend/tests/`, `docs/` | Prevents leaking developer scan DBs, test fixtures or git history into images. |

### 3.2 Read-only runtime bind mounts into `api` (and `migrate`)

So that `api` can run with `read_only: true` and without models or external data baked into
its image, `compose.yaml` bind-mounts only the required runtime artifacts **read-only (`:ro`)**:

| Host path | Container path (`api`) | Mode | Purpose |
| --- | --- | --- | --- |
| `./ml/models/deployed_char.joblib` | `/app/ml/models/deployed_char.joblib` | `:ro` | Frozen deployed TF-IDF LightGBM text model artifact |
| `./ml/models/deployment_model.json` | `/app/ml/models/deployment_model.json` | `:ro` | Frozen text deployment metadata |
| `./ml/models/url_host_v3.joblib` | `/app/ml/models/url_host_v3.joblib` | `:ro` | Frozen v4 URL model artifact (`ee0ba9f0077c1fd140aa`) |
| `./ml/models/url_host_deployment.json` | `/app/ml/models/url_host_deployment.json` | `:ro` | Frozen v4 URL deployment metadata |
| `./data/external/public_suffix_list.dat` | `/app/data/external/public_suffix_list.dat` | `:ro` | Offline Public Suffix List snapshot bind-mounted read-only (§7 Q3; kept out of git and out of images) |
| `./evaluation/reports/2026-10-v3/public_suffix_list.dat` | `/app/evaluation/reports/2026-10-v3/public_suffix_list.dat` | `:ro` | Offline Public Suffix List snapshot path referenced by `app/engines/url_model.py` (**verified** at line 14 of `url_model.py`) |
| `./data/attack-lock.json` | `/app/data/attack-lock.json` | `:ro` | ATT&CK v20.0 lock file (also mounted `:ro` into `migrate`) |
| `./data/external/attack` | `/app/data/external/attack` | `:ro` | Optional pinned ATT&CK v20.0 STIX files (mounted into `migrate` for catalogue loading; if absent, platform degrades honestly to "catalogue not installed", core v1 §4.1) |

If an optional artifact is absent on the host, `/health/ready` reports the corresponding
component or engine as degraded/unavailable without crashing the server.

---

## 4. Runtime secrets and `.env` lifecycle

### 4.1 Host-side `.env` preparation (before `docker compose up`)

In the current `compose.yaml` (**verified**), `migrate` runs `python scripts/initialize.py`,
which attempts to read and write `/app/.env` inside the container. Under a read-only root
filesystem where `.env` is not mounted into the container, `migrate` must **not** edit
`.env`. Instead:

1. **Host preparation command (`python scripts/initialize.py --env-only`):**
   - Run once on the host before starting Compose.
   - If `.env` does not exist on the host, copies `.env.example` to `.env`.
   - Calls `ensure_env_secrets(env)` to populate missing values with cryptographic random
     bytes from `secrets`, **never overwriting any existing non-empty key** ([core v2](core-v2.md)
     §3.2):
     - `ETIS_DB_PASSWORD` (24 random bytes hex)
     - `ETIS_API_KEY` (32 random bytes URL-safe)
     - `ETIS_HOST_PSEUDONYM_KEY` (32 random bytes hex)
     - `ETIS_MALWARE_PSEUDONYM_KEY` (32 random bytes hex)
     - `ETIS_SERVER_REF_KEY` (32 random bytes hex; server-only key for `srv:` device and
       account wrapping)
     - `ETIS_STIX_NAMESPACE` (random UUID4 for deterministic STIX 2.1 IDs)
   - Validates `ETIS_LAN_BIND_IP` (defaulting to `127.0.0.1` until the operator sets the
     server's RFC 1918 LAN IP).
2. **In-container migration command (`python scripts/initialize.py --db-only`):**
   - Run by the `migrate` container (`read_only: true`).
   - Requires the secrets from environment variables (failing closed with a fixed reason code
     if `ETIS_API_KEY`, `ETIS_DB_PASSWORD` or `ETIS_SERVER_REF_KEY` is missing), runs
     `alembic upgrade head`, seeds `populate_registry(db)`, `seed_correlation_stoplist(db)`,
     and `load_catalogue(db)`, and never touches `.env` on disk.

### 4.2 Least-privilege secret distribution across containers

Not every container receives every secret:

| Secret in host `.env` | `database` | `migrate` | `api` | `worker` | `web` | `reverse-proxy` |
| --- | --- | --- | --- | --- | --- | --- |
| `ETIS_DB_PASSWORD` (`DATABASE_URL`) | Yes (`POSTGRES_PASSWORD`) | Yes | Yes | Yes | **No** | **No** |
| `ETIS_API_KEY` | **No** | **No** | Yes | **No** | Yes | **No** |
| `ETIS_SERVER_REF_KEY` | **No** | **No** | Yes | **No** | **No** | **No** |
| `ETIS_HOST_PSEUDONYM_KEY` | **No** | **No** | Yes | **No** | **No** | **No** |
| `ETIS_MALWARE_PSEUDONYM_KEY` | **No** | **No** | Yes | **No** | **No** | **No** |
| `ETIS_STIX_NAMESPACE` | **No** | **No** | Yes | **No** | **No** | **No** |
| `lan-server.key` (TLS private key) | **No** | **No** | **No** | **No** | **No** | Yes (`:ro` mount) |

---

## 5. Backup, restore and upgrade procedures

All PostgreSQL CLI flags and volume behaviours below are **to verify** against the official
PostgreSQL 16 and Docker Compose documentation (§10 P1–P3, D2).

### 5.1 Database and key backup

> **Critical invariant ([core v2](core-v2.md) §3.2):** Every stored device and account
> reference in `devices`, `findings.evidence` and `finding_devices` is wrapped with
> `ETIS_SERVER_REF_KEY` (`srv:<32 hex>`). A database backup restored without the exact
> `.env` containing its `ETIS_SERVER_REF_KEY` (and `ETIS_HOST_PSEUDONYM_KEY` /
> `ETIS_STIX_NAMESPACE`) will split device and account histories on all subsequent Findings.
> Therefore, **backing up the database always requires backing up `.env` alongside it**.

1. **Create a consistent online database dump** into ignored `var/backups/` on the host:
   ```powershell
   docker compose exec -T database pg_dump -U etis -d etis --format=custom --no-owner --no-privileges > var/backups/etis-db-YYYYMMDDTHHMMSSZ.dump
   ```
   (`pg_dump` runs inside a single repeatable-read snapshot transaction without stopping the
   server; exact flags **to verify**, §10 P2).
2. **Verify and protect the backup:**
   - Record the backup file's SHA-256 and verify that `.env` (specifically
     `ETIS_SERVER_REF_KEY`) is backed up in the operator's offline secret store.
   - Expire and securely delete database backups older than `ETIS_RETENTION_DAYS` (default
     30 days) so that expired scan and sensor records do not persist indefinitely in old
     backup archives (`SETUP.md`).

### 5.2 Database restore

1. **Stop writer services while keeping `database` healthy:**
   ```powershell
   docker compose stop reverse-proxy web api worker
   ```
2. **Verify `.env` on the host** holds the `ETIS_SERVER_REF_KEY` matching the backup.
3. **Restore the custom dump cleanly into the `etis` database** (**to verify** exact
   `pg_restore --clean --if-exists --no-owner --no-privileges --single-transaction` behavior
   on PostgreSQL 16, §10 P2):
   ```powershell
   Get-Content -AsByteStream var/backups/etis-db-YYYYMMDDTHHMMSSZ.dump | docker compose exec -T database pg_restore -U etis -d etis --clean --if-exists --no-owner --no-privileges --single-transaction
   ```
4. **Run `migrate` to ensure schema and seeded stoplist/catalogue match current code:**
   ```powershell
   docker compose run --rm migrate
   ```
5. **Start all services and check health:**
   ```powershell
   docker compose up -d
   ```

### 5.3 Upgrade steps (code and Alembic migrations)

1. **Pre-upgrade backup:** Run §5.1 (`pg_dump`) and confirm exit code `0` and non-zero file
   size before changing any container or migration.
2. **Rebuild images from pinned base images:**
   ```powershell
   docker compose build
   ```
3. **Apply forward Alembic migrations:**
   ```powershell
   docker compose run --rm migrate
   ```
   - Runs `alembic upgrade head` (migrations `001` through `009_finding_devices` and
     `010_agent_devices` when present) plus idempotent registry, stoplist and ATT&CK
     catalogue seeding.
   - If upgrading an installation that stored `hmac:` device/account refs before core v2,
     run the one-off idempotent re-wrap script once ([core v2](core-v2.md) §3.2):
     ```powershell
     docker compose run --rm api python data/scripts/rewrap_device_refs.py
     ```
   - **No automatic downgrade:** Container startup never runs `alembic downgrade`. Rolling
     back a schema change uses the §5.2 pre-upgrade backup restore, and migration `005`
     refuses destructive downgrade when `incident_events` is non-empty ([core v1](core-v1.md)
     §7.2).
4. **Recreate running services and verify readiness:**
   ```powershell
   docker compose up -d
   ```

---

## 6. Threat model

| Adversary / threat | Mitigation in this design | Residual limitation (stated honestly) |
| --- | --- | --- |
| **T1. Secret leakage through Docker image layers, build cache or image export** | `.env`, `.env.*`, `var/certs/`, models and datasets are excluded by `.dockerignore`. No `Dockerfile` contains `ENV` or `ARG` secrets or `COPY .env*`. Secrets are injected at container creation from host `.env` only, with per-service least privilege (§4.2). | Any root user or `docker`-group member on the host machine can inspect running container environments (`docker inspect`) or read `.env` directly. Host OS access must be restricted to the operator. |
| **T2. Unintended exposure of PostgreSQL, FastAPI or console beyond the LAN** | `database`, `api`, `migrate`, `worker` and `web` publish zero ports. `reverse-proxy` binds only `${ETIS_LAN_BIND_IP}:8443:8443`, validated as a private RFC 1918 / ULA / loopback address. `database` sits on `etis_db_net` (`internal: true`, no default gateway). | Note (**to verify**, §10 D5): on Linux hosts, Docker's `ports:` publishing manipulates `iptables` `DOCKER` chains and can bypass `ufw`/`firewalld` default input rules unless bound to the specific LAN IP (`ETIS_LAN_BIND_IP`) and checked against host firewall rules. |
| **T3. LAN eavesdropping or active MITM between employee agents / operator browser and the LAN server** | All LAN traffic enters through `reverse-proxy` on port `8443` over HTTPS (TLS 1.3 / 1.2). Windows agents pin the server leaf certificate's DER SHA-256 fingerprint (`primary_cert_sha256` / `next_cert_sha256`, [windows-agent-lan-v1](windows-agent-lan-v1.md) §4.2). Console session cookies set `Secure; HttpOnly; SameSite=Strict`. | Operator browsers accessing `https://<LAN-IP>:8443` with a self-signed server certificate must either trust the operator-generated local CA/certificate or confirm its SHA-256 fingerprint out-of-band. |
| **T4. Container compromise via vulnerable dependency or RCE in web/api** | Containers run as unprivileged non-root UIDs (`10001:10001` / `10002:10002` / `101:101`), with `read_only: true` root filesystems, `noexec,nosuid,nodev` `tmpfs` mounts, `cap_drop: ["ALL"]` and `no-new-privileges:true`. `web` has no database credentials or `ETIS_SERVER_REF_KEY`. | A memory-only compromise inside `api` still has access to `api`'s own environment (`DATABASE_URL`, `ETIS_SERVER_REF_KEY`) while running. |
| **T5. Supply-chain drift from mutable Docker base image tags** | Every base image and service image is pinned by exact version and `@sha256:<digest>`, and Python/npm packages install from committed lock files (`requirements-windows.lock.txt` / `requirements-runtime.txt` and `etis-frontend/package-lock.json` via `npm ci`). | Base image security updates require an explicit, reviewed commit updating the pinned `@sha256:` digest. |
| **T6. Loss of database or `ETIS_SERVER_REF_KEY` mismatch on restore** | Named volume `etis_pgdata` survives `docker compose down`. §5.1 pairs every `pg_dump` backup with a verified `.env` backup so `ETIS_SERVER_REF_KEY` is never lost or mismatched. | Running `docker compose down -v` deletes named volumes; operator documentation explicitly warns never to pass `-v` in production. |

---

## 7. Open questions (resolved 27 November 2026)

1. **Q1. Reverse-proxy implementation choice:** Should TLS termination and `/agent/v1/*` vs
   `/` + `/api/*` routing use a dedicated pinned **`nginxinc/nginx-unprivileged`** (or
   **`caddy`**) container in front of `web` (`etis-frontend/server.mjs`) and `api`, **or**
   should `etis-frontend/server.mjs` itself listen via Node's built-in `node:https` when
   `ETIS_TLS_CERT_FILE` and `ETIS_TLS_KEY_FILE` are set (avoiding a third runtime base image
   while keeping one reverse proxy container)?
   - **Owner answer (27 November 2026):** Option A — a dedicated `nginxinc/nginx-unprivileged`
     proxy container, pinned by exact tag AND `@sha256:` digest.
2. **Q2. Outbound internet access for `worker` (feed refresh) on the company LAN:** On the
   LAN server, should the hourly feed worker (`manage_intelligence.py --watch`, which fetches
   PhishTank and OpenPhish over HTTPS) be enabled by default on an external-egress network,
   or should the LAN server default to **offline / manual feed sync** (`profiles: ["feeds"]`)
   so that every container in the default stack runs on `internal: true` networks with zero
   internet access?
   - **Owner answer (27 November 2026):** Yes — the feed worker goes behind an opt-in profile
     `"feeds"` (`profiles: ["feeds"]`); the default LAN stack stays on the internal network.
3. **Q3. Location of the offline Public Suffix List file (`public_suffix_list.dat`):**
   `backend/app/engines/url_model.py` currently reads
   `evaluation/reports/2026-10-v3/public_suffix_list.dat` (**verified**). Since `evaluation/`
   and `data/external/` never go into an image, how should `public_suffix_list.dat` be provided
   at runtime?
   - **Owner answer (27 November 2026):** Bind-mount `data/external/public_suffix_list.dat`
     read-only (`:ro`); keep it out of git and out of images.
4. **Q4. Local availability of Docker Desktop / Docker Engine:** `SETUP.md` notes that Docker
   is not installed on the current graduation-project Windows PC. Will the implementation
   steps be verified in this checkout via static Compose/Dockerfile/config contract tests in
   `pytest` (and on a machine or CI runner with Docker installed before release)?
   - **Owner answer (27 November 2026):** Yes — `pytest` tests stay offline static/contract
     tests; `docker compose build` / `up` is verified by hand in step 5.

---

## 8. Test plan

Because Docker may not be installed on the development machine (`SETUP.md` §Docker Compose),
the test suite is split into **deterministic offline contract tests** (run by `pytest` on
every machine without requiring a Docker daemon) and **live container smoke tests** (run
whenever Docker Engine is available):

1. **Dockerfile & `.dockerignore` static contract tests (`test_docker_lan_config.py`):**
   - Parse `Dockerfile` and `etis-frontend/Dockerfile`:
     - Assert every `FROM` instruction pins an exact version tag and `@sha256:[0-9a-f]{64}`
       digest (no floating tags).
     - Assert a non-root `USER` instruction is present before `CMD`/`ENTRYPOINT`.
     - Assert no `COPY` or `ADD` instruction references `.env`, `ml/models`, `ml/data`,
       `data/external`, `data/raw`, `data/processed`, `data/private`, `evaluation`, `var` or
       `release-artifacts`.
     - Assert no `ARG` or `ENV` instruction names a secret key (`ETIS_API_KEY`,
       `ETIS_DB_PASSWORD`, `ETIS_HOST_PSEUDONYM_KEY`, `ETIS_MALWARE_PSEUDONYM_KEY`,
       `ETIS_SERVER_REF_KEY`, `ETIS_STIX_NAMESPACE`).
   - Parse `.dockerignore`:
     - Assert every forbidden path in §3.1 is matched and excluded.
2. **Compose specification & least-privilege tests (`test_docker_lan_config.py`):**
   - Load `compose.yaml`:
     - Assert every `image:` carries an `@sha256:[0-9a-f]{64}` digest.
     - Assert `database`, `migrate`, `api`, `worker` and `web` have **no** `ports:` key.
     - Assert `reverse-proxy` binds only `${ETIS_LAN_BIND_IP...:8443:8443}` (never unprefixed
       `8443:8443` or `0.0.0.0:8443:8443`).
     - Assert every service sets `read_only: true`, non-root `user:` (or Dockerfile `USER`),
       `security_opt: ["no-new-privileges:true"]` and `cap_drop: ["ALL"]` (except any
       documented PostgreSQL entrypoint capability verified in §10 D3).
     - Assert every long-running service (`database`, `api`, `web`, `reverse-proxy`,
       `worker`) defines a `healthcheck`.
     - Assert `database` uses the named volume `etis_pgdata` and is attached only to
       `internal: true` network(s).
     - Assert `web` and `reverse-proxy` environments do **not** receive `ETIS_DB_PASSWORD` or
       `ETIS_SERVER_REF_KEY`.
     - Assert all runtime model and certificate bind mounts end with `:ro`.
3. **Host `.env` preparation and `--db-only` migration split tests (`test_docker_lan_init.py`):**
   - Test `scripts/initialize.py --env-only` in an isolated `tmp_path`: generates all
     required secrets (`ETIS_DB_PASSWORD`, `ETIS_API_KEY`, `ETIS_HOST_PSEUDONYM_KEY`,
     `ETIS_MALWARE_PSEUDONYM_KEY`, `ETIS_SERVER_REF_KEY`, `ETIS_STIX_NAMESPACE`), refuses
     non-LAN `ETIS_LAN_BIND_IP` values (`0.0.0.0`, `8.8.8.8`), and never overwrites existing
     keys on a second run.
   - Test `scripts/initialize.py --db-only` with the working directorychmodded/mocked
     read-only: succeeds without writing `.env` when environment variables are set, and fails
     closed when a required secret is missing.
4. **Reverse-proxy routing & backup/restore helper tests (`test_docker_lan_proxy_and_backup.py`):**
   - Verify reverse-proxy configuration routes `/agent/v1/*` to `api:8000` without
     `X-API-Key` and with access logs off, routes `/` and `/api/*` to `web:5173`, and blocks
     `/extension/v1/*` from LAN clients (`404`).
   - Test backup/restore helper script dry-run and validation logic (refuses restore if
     `ETIS_SERVER_REF_KEY` is missing or does not match the backup manifest's key fingerprint
     HMAC).

---

## 9. Step plan with tests per step

Each step is a separate small commit after this design is reviewed and the open questions in
§7 are answered.

| Step | Commit message | Scope | Tests for this step |
| --- | --- | --- | --- |
| 0 | `docs: Docker Compose LAN server deployment design v1` | This design document (`docs/design/docker-lan-v1.md`). | Design review only; no code or config changes. |
| 1 | `chore: pin Docker base images and harden .dockerignore` | Verify exact tags and `@sha256:` digests (§10 D1); update `.dockerignore`, `Dockerfile` and `etis-frontend/Dockerfile` (remove `COPY ml/models` and `COPY ml/data`, add non-root `USER`, pin digests). | `pytest backend/tests/test_docker_lan_config.py -k "dockerfile or dockerignore"`: asserts digests, non-root `USER`, no baked models/datasets/secrets, and complete `.dockerignore` coverage. |
| 2 | `feat: split host env generation from read-only container db init` | Add `--env-only` and `--db-only` flags to `scripts/initialize.py` (with `ETIS_LAN_BIND_IP` locality check and all core v1/v2 secret keys) so `migrate` runs on a `read_only: true` rootfs without touching `.env`. | `pytest backend/tests/test_docker_lan_init.py`: tests `--env-only` idempotence and locality validation, and `--db-only` on a read-only directory. |
| 3 | `feat: harden compose.yaml for LAN-only TLS, non-root and read-only services` | Update `compose.yaml` (and reverse-proxy config per §7 Q1): pinned digests, `read_only: true`, `tmpfs`, `no-new-privileges`, `cap_drop`, per-service healthchecks, `:ro` runtime model/cert mounts, internal networks, named volume `etis_pgdata`, and least-privilege secret injection. | `pytest backend/tests/test_docker_lan_config.py` and `pytest backend/tests/test_proxy_routes.py`: validates every Compose security invariant, port binding, `:ro` mount and proxy route rule. |
| 4 | `feat: add PostgreSQL LAN backup, restore and key-fingerprint verification scripts` | Add `scripts/lan_backup.py` and `scripts/lan_restore.py` (wrapping `pg_dump` / `pg_restore` and checking a non-secret HMAC fingerprint of `ETIS_SERVER_REF_KEY` so a backup cannot be accidentally restored under a different server ref key) and update `SETUP.md` and `.env.example`. | `pytest backend/tests/test_docker_lan_backup.py`: tests command generation, key-fingerprint mismatch refusal, backup retention cleanup, and non-zero dump verification with mocked subprocess calls. |
| 5 | Manual live Docker verification (on a Docker host) | Verify `docker compose build`, `docker compose run --rm migrate`, `docker compose up -d`, container healthchecks, and HTTPS reverse-proxy routing on a machine with Docker Engine installed. | Manual `docker compose ps`, `curl --cacert var/certs/lan-server.crt https://<ETIS_LAN_BIND_IP>:8443/healthz`, and backup/restore round-trip check. |

---

## 10. To verify (before the step that depends on it)

| # | Item to verify | Primary source to read | Needed by step |
| --- | --- | --- | --- |
| D1 | Exact current version tags and multi-arch / `linux/amd64` SHA-256 manifest digests for `python:3.12.10-slim-bookworm` (`@sha256:TO_VERIFY_python`), `node:22.12.0-bookworm-slim` (`@sha256:TO_VERIFY_node`), `postgres:16.8-bookworm` (`@sha256:TO_VERIFY_postgres`), and `nginxinc/nginx-unprivileged:1.27.4-bookworm` (`@sha256:TO_VERIFY_nginx_unprivileged`). Run on a machine with Docker installed before step 5: `docker buildx imagetools inspect <image:tag> --format "{{json .Manifest.Digest}}"`. | Official Docker Hub registry manifests / `docker buildx imagetools inspect <image:tag> --format "{{json .Manifest.Digest}}"` | 5 |
| D2 | Docker Compose Specification support and exact syntax for `read_only: true`, `tmpfs` mount options (`size`, `noexec`, `nosuid`, `nodev`), `security_opt: ["no-new-privileges:true"]`, `cap_drop: ["ALL"]`, `depends_on` conditions (`service_healthy`, `service_completed_successfully`), and `${VAR:?error}` interpolation. | Official Compose Specification (`docs.docker.com/reference/compose-file/`) | 3 |
| D3 | Official `postgres:16` Docker image behavior when run with a non-root `user: "999:999"` (or default entrypoint privilege drop), `read_only: true`, `cap_drop: ["ALL"]`, `tmpfs` at `/tmp` and `/var/run/postgresql`, and `PGDATA=/var/lib/postgresql/data/pgdata` on a fresh named volume. | Official PostgreSQL Docker image documentation (`hub.docker.com/_/postgres` and `github.com/docker-library/postgres`) | 3 |
| D4 | Writable paths required by `nginxinc/nginx-unprivileged` (or `node:https` in `etis-frontend/server.mjs`) under `read_only: true` (`tmpfs` mounts for `/tmp`, `/var/cache/nginx`, `/var/run`). | Official `nginxinc/nginx-unprivileged` documentation (`github.com/nginxinc/docker-nginx-unprivileged`) or Node.js 22 `https` documentation (`nodejs.org/docs/latest-v22.x/api/https.html`) | 3 |
| D5 | Docker port-publishing interaction with host firewalls on Linux (`iptables` `DOCKER-USER` chain) and Windows Docker Desktop when binding `${ETIS_LAN_BIND_IP}:8443:8443`. | Official Docker documentation: *Packet filtering and firewalls* (`docs.docker.com/engine/network/packet-filtering-firewalls/`) | 3, 4 |
| P1 | PostgreSQL 16 `PGDATA` subdirectory recommendation on mount points (`/var/lib/postgresql/data/pgdata`) and `pg_isready` exit codes. | Official PostgreSQL 16 documentation: `initdb` and `pg_isready` (`www.postgresql.org/docs/16/app-pg-isready.html`) | 3 |
| P2 | Exact PostgreSQL 16 `pg_dump --format=custom --no-owner --no-privileges` and `pg_restore --clean --if-exists --no-owner --no-privileges --single-transaction` behavior and error codes (`--exit-on-error`). | Official PostgreSQL 16 documentation: `pg_dump` (`www.postgresql.org/docs/16/app-pgdump.html`) and `pg_restore` (`www.postgresql.org/docs/16/app-pgrestore.html`) | 4 |
| P3 | Alembic `upgrade head` transactional DDL behavior on PostgreSQL 16 across migrations `001`–`010`. | Official Alembic documentation (`alembic.sqlalchemy.org/en/latest/branches.html`) and existing `backend/tests/test_core_migrations.py` | 2, 4 |

---

## Sources

Read locally in this repository (**verified** facts on existing Dockerfiles, Compose setup,
environment variables, migrations and proxy behavior):

- `Dockerfile`, `etis-frontend/Dockerfile`, `compose.yaml`, `.dockerignore`,
  `etis-frontend/.dockerignore`, `.gitignore`, `.env.example`, `SETUP.md`,
  `LOCAL-IMPLEMENTATION.md`
- `scripts/initialize.py`, `etis-frontend/server.mjs`, `etis-frontend/proxy-routes.mjs`,
  `backend/app/engines/url_model.py`, `backend/app/engines/host/pseudonyms.py`
- [Core v1 design](core-v1.md) (§7.2 migrations and retention)
- [Core v2 design](core-v2.md) (§1.6 `ETIS_STIX_NAMESPACE`, §3.2 `ETIS_SERVER_REF_KEY` key
  lifetime and backup requirement)
- [Windows agent and LAN server v1 design](windows-agent-lan-v1.md) (§4.2 LAN HTTPS with
  pinned server certificate, §5.1 `/agent/v1/*` endpoints)
- [Local browser extension v1 design](browser-extension-v1.md) (§2.2 loopback-only
  `/extension/v1/*` routes)

Unopened official reading sources, all **to verify** before the step that depends on them
(§10):

- Docker Compose File Reference: `https://docs.docker.com/reference/compose-file/`
- Docker Packet Filtering and Firewalls: `https://docs.docker.com/engine/network/packet-filtering-firewalls/`
- PostgreSQL 16 Documentation (`pg_dump`, `pg_restore`, `pg_isready`): `https://www.postgresql.org/docs/16/reference-client.html`
- Official PostgreSQL Docker Image Repository: `https://github.com/docker-library/postgres`
- NGINX Unprivileged Docker Image Repository: `https://github.com/nginxinc/docker-nginx-unprivileged`
