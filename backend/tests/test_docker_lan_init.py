"""Tests for host .env generation (--env-only) and read-only container DB init (--db-only) (docker-lan-v1.md §8.3)."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import initialize as init_mod  # noqa: E402


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        k, v = stripped.split("=", 1)
        values[k.strip()] = v.strip()
    return values


def test_env_only_generates_all_required_secrets_and_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env.example").write_text(
        "ETIS_API_KEY=\nETIS_TEXT_MODEL=char\nETIS_HOST_PSEUDONYM_KEY=\nETIS_MALWARE_PSEUDONYM_KEY=\n",
        encoding="utf-8",
    )
    called_db = False

    def _forbid_db(*args, **kwargs):
        nonlocal called_db
        called_db = True

    monkeypatch.setattr(init_mod, "run_db_migrations_and_seed", _forbid_db)

    res = init_mod.initialize(env_only=True, root=tmp_path)
    assert res["initialized"] is True
    assert res["mode"] == "env-only"
    assert called_db is False

    env_path = tmp_path / ".env"
    assert env_path.is_file()
    first = _parse_env_file(env_path)

    assert len(first["ETIS_API_KEY"]) >= 32
    assert re.fullmatch(r"[0-9a-f]{48}", first["ETIS_DB_PASSWORD"])
    for key_name in ("ETIS_HOST_PSEUDONYM_KEY", "ETIS_MALWARE_PSEUDONYM_KEY", "ETIS_SERVER_REF_KEY"):
        assert re.fullmatch(r"[0-9a-f]{64}", first[key_name]), f"{key_name} must be 32 hex bytes"
    uuid.UUID(first["ETIS_STIX_NAMESPACE"])
    assert first["ETIS_LAN_BIND_IP"] == "127.0.0.1"

    # Second run must preserve every existing secret unchanged (core-v2 §3.2).
    init_mod.initialize(env_only=True, root=tmp_path)
    second = _parse_env_file(env_path)
    assert second == first


@pytest.mark.parametrize(
    "valid_ip",
    ["127.0.0.1", "10.0.0.15", "172.16.4.20", "192.168.1.50", "fd00::10"],
)
def test_validate_lan_bind_ip_accepts_private_and_loopback_addresses(valid_ip: str) -> None:
    assert init_mod.validate_lan_bind_ip(valid_ip) == valid_ip


@pytest.mark.parametrize(
    "forbidden_ip",
    ["0.0.0.0", "::", "8.8.8.8", "1.1.1.1", "93.184.216.34", "", "not-an-ip", "0.0.0.0:8443"],
)
def test_validate_lan_bind_ip_rejects_wildcard_and_public_addresses(
    tmp_path: Path, forbidden_ip: str
) -> None:
    with pytest.raises(ValueError, match="invalid_lan_bind_ip"):
        init_mod.validate_lan_bind_ip(forbidden_ip)

    if forbidden_ip:
        env_path = tmp_path / ".env"
        env_path.write_text(f"ETIS_LAN_BIND_IP={forbidden_ip}\n", encoding="utf-8")
        with pytest.raises(ValueError, match="invalid_lan_bind_ip"):
            init_mod.ensure_env_secrets(env_path)


def test_db_only_never_touches_env_file_and_succeeds_with_runtime_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://etis:secret@database:5432/etis")
    monkeypatch.setenv("ETIS_API_KEY", "test-api-key-1234567890")
    monkeypatch.setenv("ETIS_SERVER_REF_KEY", "a" * 64)

    def _forbid_env_write(*args, **kwargs):
        raise AssertionError("--db-only must never call ensure_env_secrets or write .env")

    monkeypatch.setattr(init_mod, "ensure_env_secrets", _forbid_env_write)
    monkeypatch.setattr(init_mod, "run_db_migrations_and_seed", lambda root, seed=False: {"status": "loaded"})

    result = init_mod.initialize(db_only=True, root=tmp_path)
    assert result["initialized"] is True
    assert result["mode"] == "db-only"
    assert not (tmp_path / ".env").exists()


def test_db_only_fails_closed_when_required_secret_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("ETIS_DB_PASSWORD", raising=False)
    monkeypatch.delenv("ETIS_API_KEY", raising=False)
    monkeypatch.delenv("ETIS_SERVER_REF_KEY", raising=False)

    with pytest.raises(RuntimeError, match="missing_required_runtime_secret"):
        init_mod.initialize(db_only=True, root=tmp_path)


def test_conflicting_env_only_and_db_only_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="conflicting_initialize_modes"):
        init_mod.initialize(env_only=True, db_only=True, root=tmp_path)
