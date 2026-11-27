"""Initialize only the configured local project database; never connect to a previous checkout implicitly."""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.engines.host.pseudonyms import locality  # noqa: E402

PSEUDONYM_KEYS = ("ETIS_HOST_PSEUDONYM_KEY", "ETIS_MALWARE_PSEUDONYM_KEY", "ETIS_SERVER_REF_KEY")
REQUIRED_DB_ONLY_SECRETS = ("ETIS_API_KEY", "ETIS_SERVER_REF_KEY")


def validate_lan_bind_ip(address: str) -> str:
    """Accept only private RFC 1918, IPv6 ULA, link-local, or loopback literals; reject 0.0.0.0 and public IPs."""
    cleaned = (address or "").strip()
    if locality(cleaned) != "local":
        raise ValueError("invalid_lan_bind_ip")
    return cleaned


def _set_or_fill_key(content: str, name: str, generator) -> str:
    match = re.search(r"^" + re.escape(name) + r"=(.*)$", content, re.M)
    if match is None:
        new_val = generator()
        prefix = content.rstrip("\n")
        return (prefix + "\n" if prefix else "") + f"{name}={new_val}\n"
    if not match.group(1).strip():
        new_val = generator()
        return content[: match.start()] + f"{name}={new_val}" + content[match.end() :]
    return content


def ensure_env_secrets(env: Path, template_path: Path | None = None) -> None:
    """Add missing local secrets to .env (creating from .env.example if needed); never replace an existing value."""
    if not env.exists():
        tpl = template_path if template_path is not None else (env.parent / ".env.example")
        initial = tpl.read_text(encoding="utf-8") if tpl.exists() else ""
        env.write_text(initial, encoding="utf-8")

    content = env.read_text(encoding="utf-8")
    content = _set_or_fill_key(content, "ETIS_API_KEY", lambda: secrets.token_urlsafe(32))
    content = _set_or_fill_key(content, "ETIS_DB_PASSWORD", lambda: secrets.token_hex(24))

    # Dedicated HMAC keys, 32 random bytes each: host pseudonyms (docs/design/host-engine-v1.md section 6.4),
    # malware path_ref (docs/design/malware-engine-v1.md section 7) and the server-only key that wraps stored
    # device and account refs to srv: (docs/design/core-v2.md section 3.2). An existing value is never replaced:
    # rotating or losing ETIS_SERVER_REF_KEY would split every stored ref, and rotation is out of scope.
    for name in PSEUDONYM_KEYS:
        content = _set_or_fill_key(content, name, lambda: secrets.token_hex(32))

    # Per-installation namespace for deterministic STIX ids (docs/design/core-v2.md section 1.6). Never replaced.
    content = _set_or_fill_key(content, "ETIS_STIX_NAMESPACE", lambda: str(uuid.uuid4()))

    # LAN reverse-proxy bind IP (docs/design/docker-lan-v1.md §2.3, §4.1); defaults to 127.0.0.1 until set to LAN IP.
    content = _set_or_fill_key(content, "ETIS_LAN_BIND_IP", lambda: "127.0.0.1")
    bind_match = re.search(r"^ETIS_LAN_BIND_IP=(.*)$", content, re.M)
    if bind_match is not None:
        validate_lan_bind_ip(bind_match.group(1))

    env.write_text(content, encoding="utf-8")


def verify_db_only_env(environ: Mapping[str, str] | None = None) -> None:
    """Fail closed if required runtime secrets are missing when running --db-only inside a read-only container."""
    env_map = environ if environ is not None else os.environ
    has_db = bool(env_map.get("DATABASE_URL", "").strip() or env_map.get("ETIS_DB_PASSWORD", "").strip())
    if not has_db:
        raise RuntimeError("missing_required_runtime_secret")
    for name in REQUIRED_DB_ONLY_SECRETS:
        if not env_map.get(name, "").strip():
            raise RuntimeError("missing_required_runtime_secret")


def run_db_migrations_and_seed(root: Path = ROOT, seed: bool = False) -> object:
    """Run Alembic upgrade head and idempotent registry/stoplist/ATT&CK seeding without touching .env on disk."""
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=root, check=True)
    if str(root / "backend") not in sys.path:
        sys.path.insert(0, str(root / "backend"))
    from app.core.database import SessionLocal
    from app.services.attack import load_catalogue
    from app.services.findings import seed_correlation_stoplist
    from app.services.registry import populate_registry

    with SessionLocal() as db:
        populate_registry(db)
    with SessionLocal() as db:
        seed_correlation_stoplist(db)
    # Local pinned files only (data/scripts/fetch_attack.py); absent files leave the catalogue not installed.
    with SessionLocal() as db:
        attack = load_catalogue(db)
    if seed:
        subprocess.run([sys.executable, "data/scripts/seed_database.py", "--mode", "archive"], cwd=root, check=True)
    return attack


def initialize(
    seed: bool = False,
    *,
    env_only: bool = False,
    db_only: bool = False,
    root: Path = ROOT,
) -> dict[str, object]:
    if env_only and db_only:
        raise ValueError("conflicting_initialize_modes")

    env = root / ".env"
    if env_only:
        ensure_env_secrets(env, template_path=root / ".env.example")
        result: dict[str, object] = {
            "initialized": True,
            "mode": "env-only",
            "key": "stored in ignored .env; never printed",
        }
        print(json.dumps(result))
        return result

    if db_only:
        verify_db_only_env()
        attack = run_db_migrations_and_seed(root=root, seed=seed)
        result = {
            "initialized": True,
            "mode": "db-only",
            "database": "configured DATABASE_URL",
            "attack_catalogue": attack,
        }
        print(json.dumps(result))
        return result

    if not env.exists() and not os.getenv("ETIS_API_KEY"):
        ensure_env_secrets(env, template_path=root / ".env.example")
    elif env.exists():
        ensure_env_secrets(env, template_path=root / ".env.example")
    attack = run_db_migrations_and_seed(root=root, seed=seed)
    result = {
        "initialized": True,
        "database": "project-local SQLite unless DATABASE_URL explicitly configured",
        "key": "stored in ignored .env; never printed",
        "attack_catalogue": attack,
    }
    print(json.dumps(result))
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed-archive", action="store_true")
    p.add_argument("--env-only", action="store_true", help="Generate/fill host .env secrets only; do not touch DB")
    p.add_argument("--db-only", action="store_true", help="Run DB migrations/seeding only; never read or write .env")
    args = p.parse_args()
    initialize(args.seed_archive, env_only=args.env_only, db_only=args.db_only)
