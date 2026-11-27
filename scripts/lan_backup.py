"""Create a PostgreSQL custom-format backup paired with an ETIS_SERVER_REF_KEY HMAC fingerprint (docker-lan-v1.md §5.1)."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BACKUP_DIR = ROOT / "var" / "backups"
FINGERPRINT_DOMAIN = b"etis-server-ref-key-fingerprint-v1"

# Exact PostgreSQL 16 pg_dump flags are marked "to verify" before step 5 (docs/design/docker-lan-v1.md §10 P2).
PG_DUMP_CMD = (
    "docker",
    "compose",
    "exec",
    "-T",
    "database",
    "pg_dump",
    "-U",
    "etis",
    "-d",
    "etis",
    "--format=custom",
    "--no-owner",
    "--no-privileges",
)


def read_env_map(env_file: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            values[k.strip()] = v.strip().strip("'\"")
    for k, v in os.environ.items():
        if k.startswith("ETIS_") and k not in values:
            values[k] = v.strip()
    return values


def server_ref_key_fingerprint(raw_hex_key: str) -> str:
    """Return a non-secret 32-hex HMAC fingerprint of ETIS_SERVER_REF_KEY."""
    cleaned = (raw_hex_key or "").strip()
    try:
        key_bytes = bytes.fromhex(cleaned)
    except ValueError:
        key_bytes = b""
    if len(key_bytes) < 16:
        raise ValueError("server_ref_key_missing")
    return hmac.new(key_bytes, FINGERPRINT_DOMAIN, hashlib.sha256).hexdigest()[:32]


def prune_expired_backups(backup_dir: Path, retention_days: int, *, now: float | None = None) -> list[str]:
    """Delete .dump and .manifest.json files older than retention_days."""
    if retention_days <= 0 or not backup_dir.is_dir():
        return []
    current_time = now if now is not None else time.time()
    cutoff = current_time - (retention_days * 86400)
    removed: list[str] = []
    for dump_file in sorted(backup_dir.glob("etis-db-*.dump")):
        if dump_file.stat().st_mtime < cutoff:
            manifest_file = dump_file.with_name(dump_file.name + ".manifest.json")
            dump_file.unlink(missing_ok=True)
            manifest_file.unlink(missing_ok=True)
            removed.append(dump_file.name)
    return removed


def create_backup(
    *,
    root: Path = ROOT,
    output_dir: Path | None = None,
    prune_expired: bool = False,
    runner=subprocess.run,
    now_utc: datetime | None = None,
) -> dict[str, object]:
    env_map = read_env_map(root / ".env")
    fingerprint = server_ref_key_fingerprint(env_map.get("ETIS_SERVER_REF_KEY", ""))
    try:
        retention_days = int(env_map.get("ETIS_RETENTION_DAYS", "30") or "30")
    except ValueError:
        retention_days = 30

    target_dir = output_dir if output_dir is not None else (root / "var" / "backups")
    target_dir.mkdir(parents=True, exist_ok=True)

    stamp_dt = now_utc if now_utc is not None else datetime.now(timezone.utc)
    stamp = stamp_dt.strftime("%Y%m%dT%H%M%SZ")
    dump_path = target_dir / f"etis-db-{stamp}.dump"
    manifest_path = target_dir / f"etis-db-{stamp}.dump.manifest.json"

    proc = runner(list(PG_DUMP_CMD), cwd=root, capture_output=True, check=False)
    stdout_bytes = proc.stdout if isinstance(proc.stdout, (bytes, bytearray)) else b""
    if proc.returncode != 0 or len(stdout_bytes) == 0:
        dump_path.unlink(missing_ok=True)
        raise RuntimeError("empty_or_failed_backup")

    dump_path.write_bytes(bytes(stdout_bytes))
    dump_sha256 = hashlib.sha256(stdout_bytes).hexdigest()

    manifest: dict[str, object] = {
        "created_at_utc": stamp_dt.isoformat(),
        "dump_filename": dump_path.name,
        "dump_sha256": dump_sha256,
        "dump_size_bytes": len(stdout_bytes),
        "server_ref_key_fingerprint": fingerprint,
        "retention_days": retention_days,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    pruned: list[str] = []
    if prune_expired:
        pruned = prune_expired_backups(target_dir, retention_days)

    return {
        "backup_created": True,
        "dump_path": str(dump_path),
        "manifest_path": str(manifest_path),
        "dump_sha256": dump_sha256,
        "dump_size_bytes": len(stdout_bytes),
        "server_ref_key_fingerprint": fingerprint,
        "pruned_backups": pruned,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Create a PostgreSQL LAN server backup verified against ETIS_SERVER_REF_KEY")
    p.add_argument("--output-dir", type=Path, default=None)
    p.add_argument("--prune-expired", action="store_true", help="Delete backups older than ETIS_RETENTION_DAYS")
    args = p.parse_args()
    summary = create_backup(output_dir=args.output_dir, prune_expired=args.prune_expired)
    print(json.dumps(summary))
