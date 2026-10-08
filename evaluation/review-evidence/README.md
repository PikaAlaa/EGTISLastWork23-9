# ETIS review evidence pack

Reproduces every finding in the *ETIS Final Project Review* that comes from an automated test, a measurement or a dataset analysis. Manual findings (the Windows install, the browser walkthrough and its screenshots, build output size) are recorded in the review itself and are not re-run here. Each script writes JSON to `results/`; the review's Evidence log quotes these files.

## Fixture

| Item | Value |
| --- | --- |
| Code | Mido-77/ETIS-Group, commit `bd56f3b220a9b5c6e1293b0b5b2ec42ef180f5f1`, unmodified |
| Data | `data/processed/dataset.csv` at that commit (86,692 rows) |
| Database | PostgreSQL 16.13, tables from `Base.metadata.create_all`, then `seed_database.py` at that commit: 65,090 blacklist entries (from 65,101 phishing-URL rows; 11 are exact repeats), 18 brands, 20 brand domains |
| Model | Shipped BiLSTM, tokenizer and config under `ml/` at that commit |
| API | `uvicorn app.main:app --port 8000`, no `ETIS_API_KEY`, default 20/min per-IP limit |

## Environments by test category

| Category | Scripts | Environment |
| --- | --- | --- |
| Live API cases (D, E14, robustness) | `run_api_cases.py` | Linux 6.18, Python 3.12.3, TensorFlow 2.21.0, PostgreSQL 16.13, run 1 Oct 2026 |
| Direct calls and controlled scoring (D1 parsing, D3, D6–D8, D11, E8, E10, model pairs) | `run_direct_checks.py` | Same as above; engines imported in-process, fixed engine scores via `unittest.mock` |
| Dataset and evaluation design (E1–E4, E11, E12, wording, length) | `run_dataset_checks.py` | Same Python; pandas 3.0.5; blacklist hashes read from the seeded database |
| Model comparison (E1 sensitivity, model section) | `run_model_comparison.py` | scikit-learn 1.9.0, LightGBM 4.7.0, NumPy 2.5.1 |
| Runtime (S1–S3, R10) | `run_runtime_checks.py`, `run_startup_checks.py` | Same server; CPU only, no GPU |
| Character-model probes (completion plan A3) | `run_char_model_check.py` | Same Python and scikit-learn; single-example model outputs, not accuracy |
| Offline scan (R2) | `run_offline_check.py` | New network namespace (`unshare -rn`), loopback only, PostgreSQL over its Unix socket |
| Installation (S4) | none: manual | Windows laptop, PowerShell, Python 3.12, PostgreSQL 18, following SETUP.md during the team install |
| UX (accessibility, wording) | Playwright + axe-core walkthrough | Chromium (Playwright), frontend `npm run dev` at http://localhost:5173 |
| Static findings (D9, D11, E8 code side, E9, S6–S14) | none: file and line references in the review | Commit `bd56f3b` |

## Run

```bash
export ETIS_REPO=/path/to/ETIS-Group PYTHONPATH=$ETIS_REPO/backend DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/etis
python run_api_cases.py http://127.0.0.1:8000      # about 2.5 min (spaced for the rate limit)
python run_direct_checks.py                         # reads the blacklisted URL chosen by run_api_cases.py
python run_dataset_checks.py
python run_model_comparison.py
python run_runtime_checks.py <uvicorn pid>          # about 4 min
python run_startup_checks.py                        # stop the running server first; about 3 min
unshare -rn sh -c 'ip link set lo up; DATABASE_URL="postgresql://postgres:postgres@/etis?host=/tmp" python run_offline_check.py'
python run_char_model_check.py
python summarise.py                                 # re-applies pass rules, writes results/SUMMARY.md
(cd $ETIS_REPO/backend && python -m pytest -q tests) # unit tests; results/unit_tests.txt
```

**Safety note:** `cases.py` and `results/` contain real phishing URLs from PhishTank (for example the blacklisted test URL). They're there as test data; don't open them in a browser. The pack holds no real personal messages: every SMS is invented, and digits are placeholders. The only credential is the local default `postgres:postgres` in the example command.

All inputs and the verdict each case must return are in `cases.py`; the expected verdicts are proposals for the team and supervisor to confirm. Messages are invented; phone, card and account digits are placeholders.

## Other captured outputs

- `results/server_tracebacks_D12.txt`: the server-side errors behind the two HTTP 500 responses.
- `results/unit_tests.txt`: the repository's 59 unit tests and the 13 that need the live database.

## Definitions

- **Pass** for an API case: the returned verdict (or HTTP status) is one of those listed for the case in `cases.py`. D5b is a reference case (the blacklisted URL on its own), not a defect case.
- **Hostname**: `urllib.parse.urlsplit(url).hostname`. **ETIS normaliser**: `normalize_domain`.
- **Unseen host**: hostname not among the training-split phishing hostnames.
- **Duplicate text**: lower-cased, whitespace collapsed.
- **Egyptian-targeted URL (strict)**: a host token (split on `.` and `-`) equals an Egyptian brand label or short name, or the host ends in `.eg`.
- **ECE**: 10 equal-width bins on P(phishing).
- **95% interval**: percentile bootstrap, 2,000 resamples, seed 42.
- **Baselines**: settings are in the docstring of `run_model_comparison.py`.
