from __future__ import annotations

import os
import json
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")


class Settings:
    app_name = "ETIS API"
    app_version = "0.1.0"
    database_url = os.getenv("DATABASE_URL", f"sqlite:///{PROJECT_ROOT / 'etis.db'}")
    api_key = os.getenv("ETIS_API_KEY", "").strip()
    cors_origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if item.strip()]
    model_path = Path(os.getenv("ETIS_MODEL_PATH", str(PROJECT_ROOT / "ml" / "artifacts" / "text_model.joblib")))
    bilstm_model_path = Path(os.getenv("ETIS_BILSTM_MODEL_PATH", str(PROJECT_ROOT / "ml" / "artifacts" / "bilstm.keras")))
    _calibration_path = PROJECT_ROOT / "evaluation" / "reports" / "threshold_calibration.json"
    try:
        _calibration = json.loads(_calibration_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        _calibration = {}
    medium_threshold = float(os.getenv("ETIS_MEDIUM_THRESHOLD", _calibration.get("selected_medium_threshold", 35)))
    high_threshold = float(os.getenv("ETIS_HIGH_THRESHOLD", _calibration.get("selected_high_threshold", 65)))


settings = Settings()
