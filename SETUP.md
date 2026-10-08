# ETIS local setup (Windows)

This copy implements decision-v2 from the October completion plan. It is an experimental
scanner. Routine bank messages still cause false alarms; final real-data validation is
pending. Reporting, accounts/history and Telegram remain deferred.

## Working folder

Run these commands from your cloned or extracted project folder.
Open `http://127.0.0.1:5173/scan` while the local services are running.

Start: `.\Start-ETIS.ps1`.
Stop: `.\Stop-ETIS.ps1`.
Keep this folder intact: it contains the local environment, generated models and own database.
The reviewed source is being published to `PikaAlaa/EGTISLastWork23-9` at the user's
request. Fresh clones need the installation below; local secrets and databases are
excluded. The original Mido-77 checkout's origin remains protected from pushes.

## Fresh installation

Prerequisites: Python 3.12 (or uv), Node.js 22.12 or later, npm, Git if obtaining the source again.
Run from this project folder in PowerShell:

```powershell
.\Install-ETIS.ps1 -Start
```

The installer creates an isolated environment, installs runtime dependencies, migrates
its own SQLite database, seeds the supplied brand registry, builds the interface and
starts the API, web proxy and hourly feed/retention worker. It generates random local
secrets in ignored `.env`; it never prints them. It does not change Windows security
settings or create a Windows scheduled task. The worker runs only while ETIS runs.
The selected character artifact is included; TensorFlow is optional for comparison.

To rebuild data and compare all three models before starting:

```powershell
.\Install-ETIS.ps1 -TrainCandidates -Start
```

This adds training-only synthetic notification examples, trains character, BiLSTM and
LightGBM candidates, and compares all three using grouped validation only.
It never runs final tests. September artifacts and the original dataset remain intact.
Candidate outputs, private data and local databases are ignored by Git. The deployed
artifact and deployment manifest are intended release files.

## Configuration and privacy

SQLite defaults to `var/etis.db`. No previous checkout or existing PostgreSQL database
is selected automatically. To use a different database, set `DATABASE_URL` explicitly
in `.env`, back it up, then run `python scripts/initialize.py` from this environment.
Migration 002 removes raw submissions and legacy matched snippets; that step cannot
restore raw data. Protect and expire older backups separately. Migration tests cover
fresh installation and September scan records on SQLite. PostgreSQL/Compose still
needs a run on a machine with Docker.

Runtime dependencies: `requirements-runtime.txt`. Training/TensorFlow:
`requirements-models.txt`. `requirements-windows.lock.txt` records the exact installed
Windows Python package versions used here. `etis-frontend/package-lock.json` locks npm.
For the same Python environment use `uv pip install --python .venv/Scripts/python.exe -r requirements-windows.lock.txt`.

Raw message text and submitted URL paths/query values are not stored in scan records
or logs. Hashes, verdicts, reason codes and version IDs are retained for 30 days by
default. Feed intelligence contains public phishing URLs as data; do not open them.
Link checking parses input and queries the local database; it never visits destinations.

The server-side proxy holds the API key and issues signed, HttpOnly, SameSite session
cookies. The browser gets no key. API authentication returns 401. Limits default to
20 API scans/minute/session and 60 proxy requests/minute/session/IP. Both services bind
to loopback locally. The proxy also validates Host and Origin. For an authorized public
deployment, configure an HTTPS reverse proxy, `ETIS_ALLOWED_HOSTS` and
`ETIS_SECURE_COOKIE=true`; neither public exposure nor TLS setup was performed here.

## Feed updates and failure behavior

The worker checks PhishTank and OpenPhish hourly. A failed, malformed or suspiciously
small refresh preserves the previous snapshot. Expiry is tracked per source (30 days
PhishTank, 7 OpenPhish, 90 manual); rollback preserves other sources. Scan retention
runs each cycle even after failed downloads. Logs are under ignored `var/`.

Manual refresh: `python data/scripts/manage_intelligence.py`.
Rollback: `python data/scripts/manage_intelligence.py --rollback SNAPSHOT_VERSION`.
Archival import, only if deliberately needed: `python data/scripts/seed_database.py --mode archive`.
Do not run archival imports over a current feed just to make its collection date fresh.

`/health/live` reports process liveness. `/health/ready` reports both engine states:
200 ready when both work, 200 degraded when one works, 503 when neither works.
Missing/stale required feeds make URL checks incomplete. HIGH can still apply if decisive
evidence was found; otherwise incomplete checking is never LOW. Database save failure
returns the verdict with `saved=false`. Text-only scans keep working without the database.

## Verification and evaluation

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/local_smoke.py
cd etis-frontend
npm.cmd run build
npm.cmd run lint
```

See `LOCAL-IMPLEMENTATION.md` for recorded results and unresolved acceptance criteria.
See `evaluation/README.md` for grouped data, frozen URL protocols, model comparison,
sealed SMS testing and approval gates. Numeric targets remain proposals until the
supervisor approves them. Synthetic examples never satisfy the real-message requirement.

## Docker Compose

Docker is not installed on this computer, so these files have not been executed here.
With Docker available, initialize `.env`, then run `docker compose up --build -d`.
Compose starts PostgreSQL, migrations, API, worker and web. Only the web port is exposed,
on localhost. The database password is random local configuration, not a checked-in
default. The runtime image uses the selected character model. To use BiLSTM, build with
`INCLUDE_TENSORFLOW=true`, provide its artifact/tokenizer paths and configure its backend.

Stop Compose with `docker compose down`; the named database volume remains.
