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
    # Malware scan-derived Findings and scan records (design malware-engine-v1 §7).
    malware_retention_days: int = int(os.getenv('ETIS_MALWARE_RETENTION_DAYS', '30'))
    # Network import-derived Findings and import records, shared by network.flows and network.windows
    # (design network-windows-v1 §0.1, §7).
    network_retention_days: int = int(os.getenv('ETIS_NETWORK_RETENTION_DAYS', '30'))
    # host.windows Findings (design host-engine-v1 §7); also the window for agent-submitted host Findings
    # (windows-agent-lan-v1 §7.3, owner decision Q2: the existing per-engine settings, no agent setting).
    host_retention_days: int = int(os.getenv('ETIS_HOST_RETENTION_DAYS', '30'))
    blacklist_max_age_days: int = int(os.getenv('ETIS_BLACKLIST_MAX_AGE_DAYS', '30'))
    # LAN agent pairing bundle (design windows-agent-lan-v1 §4.1, §4.2, Q5): SHA-256 of the server's DER leaf
    # certificate and an optional next one for rotation. Not secrets; empty means not configured.
    agent_primary_cert_sha256: str = os.getenv('ETIS_AGENT_PRIMARY_CERT_SHA256', '').strip().lower()
    agent_next_cert_sha256: str = os.getenv('ETIS_AGENT_NEXT_CERT_SHA256', '').strip().lower()
    required_feeds: tuple = tuple(filter(None, os.getenv('ETIS_REQUIRED_FEEDS','phishtank,openphish').split(',')))
    cors_origins: tuple = tuple(filter(None, os.getenv('ETIS_CORS_ORIGINS', '').split(',')))
    rate_limit: str = os.getenv('ETIS_RATE_LIMIT', '20/minute')
    text_low_threshold: float = float(os.getenv('ETIS_TEXT_LOW_THRESHOLD', '0.2'))
    text_high_threshold: float = float(os.getenv('ETIS_TEXT_HIGH_THRESHOLD', '0.8'))
    # Core v1 incident correlation window (design core-v1 §3.2); not a detection threshold.
    correlation_window_days: int = int(os.getenv('ETIS_CORRELATION_WINDOW_DAYS', '14'))
    # Record core v1 findings for /analyze scans (design core-v1 §5.1). Default on only
    # because the verdict parity gate (tests/test_findings_parity.py) passes; set 0 to
    # reproduce pre-core behaviour exactly.
    findings_enabled: bool = os.getenv('ETIS_FINDINGS_ENABLED', '1') == '1'
    # Show draft recommended-action texts, marked "Draft — not reviewed", for team review only
    # (design core-v2 §2.3). Off by default: unreviewed texts stay hidden.
    show_draft_actions: bool = os.getenv('ETIS_SHOW_DRAFT_ACTIONS', '0') == '1'

settings = Settings()
