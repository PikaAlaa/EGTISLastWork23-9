"""One environment-backed configuration; no deployment credentials in source."""
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / '.env')

@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv('DATABASE_URL', f'sqlite:///{(PROJECT_ROOT / "var/etis.db").as_posix()}')
    api_key: str = os.getenv('ETIS_API_KEY', '')
    model_backend: str = os.getenv('ETIS_TEXT_MODEL', 'char')
    model_path: str = str(PROJECT_ROOT / os.getenv('ETIS_CHAR_MODEL_PATH', 'ml/models/deployed_char.joblib'))
    retention_days: int = int(os.getenv('ETIS_RETENTION_DAYS', '30'))
    blacklist_max_age_days: int = int(os.getenv('ETIS_BLACKLIST_MAX_AGE_DAYS', '30'))
    required_feeds: tuple = tuple(filter(None, os.getenv('ETIS_REQUIRED_FEEDS','phishtank,openphish').split(',')))
    cors_origins: tuple = tuple(filter(None, os.getenv('ETIS_CORS_ORIGINS', '').split(',')))
    rate_limit: str = os.getenv('ETIS_RATE_LIMIT', '20/minute')
    text_low_threshold: float = float(os.getenv('ETIS_TEXT_LOW_THRESHOLD', '0.2'))
    text_high_threshold: float = float(os.getenv('ETIS_TEXT_HIGH_THRESHOLD', '0.8'))

settings = Settings()
