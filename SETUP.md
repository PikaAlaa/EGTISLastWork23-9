# ETIS local setup (Parts 1–4)

Requirements: Python 3.12 and Node.js 22. SQLite is the default; PostgreSQL is optional.

## Install and verify

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python data/scripts/validate_and_clean_dataset.py
python -m pytest -q
```

Dataset validation should report **85,992 rows** with no exact or canonical cross-split leakage. The current backend suite has **29 passing tests**.

## Seed and run

```powershell
python data/scripts/seed_database.py
cd backend
uvicorn app.main:app --reload
```

In a second terminal:

```powershell
cd etis-frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Arabic/RTL is the default; the header switch enables English/LTR.

## Configuration

Copy `.env.example` to `.env` if you need overrides. Important variables:

```dotenv
DATABASE_URL=sqlite:///./etis.db
ETIS_API_KEY=
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

When `ETIS_API_KEY` is set, the frontend must receive the same value as `VITE_ETIS_API_KEY`. Never commit real credentials.

## Rebuild data and models

The committed CSV is already cleaned. Only use `--write` after changing its source rows:

```powershell
python data/scripts/validate_and_clean_dataset.py --write
```

The cleaner canonicalizes URLs, resolves only reviewed label conflicts, groups near-duplicate messages before splitting, and writes `data/processed/dataset_cleaning_report.json`.

Retrain and evaluate in this order:

```powershell
python evaluation/baseline_sanity_check.py
python ml/train_lstm.py
python evaluation/select_text_model.py
python evaluation/calibrate_thresholds.py
python evaluation/evaluate_hybrid.py
python evaluation/run_acceptance.py
```

The vectorizers are fitted on the training split only. Model choice is made on validation F1, and the test split is reported afterward. Current held-out text/email results:

- TF-IDF logistic regression: F1 0.956989, ROC-AUC 0.996443 (selected)
- TF-IDF LightGBM: F1 0.931818, ROC-AUC 0.993683
- BiLSTM: F1 0.916667, ROC-AUC 0.984127

## Final checks

```powershell
python -m pytest -q
cd etis-frontend
npm run build
```

The local acceptance report must show every case passing. Parts 5–6 are intentionally not included.
