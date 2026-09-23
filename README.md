# ETIS — Parts 1–4

ETIS is an Egypt-specific, Arabic-aware phishing detection research prototype. This repository intentionally stops at Part 4: rules/fusion, data and ML evaluation, backend/API, and bilingual frontend.

## Completed scope

- **P1 — Rules and fusion:** Arabic credential/urgency rules with safety-warning context, Egyptian-brand typosquatting, suspicious URL analysis, canonical blacklist matching, shared-host protection, and explainable weighted fusion.
- **P2 — Data and ML:** 85,992-row locked dataset, group-aware 70/15/15 split, exact/canonical deduplication, 0.92-similarity leakage grouping, TF-IDF logistic regression, LightGBM, BiLSTM, validation-based model selection, and held-out reports.
- **P3 — Backend/API:** FastAPI, SQLite/PostgreSQL support, persistence, API-key option, rate limiting, `/analyze`, filterable `/threats`, `/stats`, error handling, and automated tests.
- **P4 — Frontend/UX:** React/TypeScript/MUI dashboard, Arabic RTL and English LTR, scan explanation, filterable threat feed, statistics breakdowns, responsive layout, and API error states.

The validation-selected production text model is TF-IDF logistic regression (held-out F1 **0.956989**, ROC-AUC **0.996443**). The BiLSTM was also trained and evaluated, but was not selected because its validation result was lower. The full hybrid test is intentionally stricter and tests unseen URLs using a blacklist built only from the training split.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python data/scripts/validate_and_clean_dataset.py
python data/scripts/seed_database.py
python -m pytest -q
```

Start the API:

```powershell
cd backend
uvicorn app.main:app --reload
```

Start the dashboard in another terminal:

```powershell
cd etis-frontend
npm install
npm run dev
```

Open `http://localhost:5173`; API documentation is at `http://localhost:8000/docs`.

See `SETUP.md` for model retraining, evaluation, environment variables, and verification commands.

## Evidence and limitations

Reports are under `evaluation/reports/`, and `acceptance_test_report.json` records the final local acceptance run. A commercial-tool comparison is not fabricated: it requires an authorized external service and API key. Deployment/QA ownership and thesis/defense work (Parts 5–6) are outside this delivery by request.
