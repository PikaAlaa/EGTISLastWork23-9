"""Restore a PostgreSQL custom-format backup after verifying its ETIS_SERVER_REF_KEY fingerprint (docker-lan-v1.md §5.2)."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.lan_backup import read_env_map, server_ref_key_fingerprint  # noqa: E402

STOP_WRITERS_CMD = (
    "docker",
    "compose",
    "stop",
    "reverse-proxy",
    "web",
    "api",
    "worker",
)

# Exact PostgreSQL 16 pg_restore flags are marked "to verify" before step 5 (docs/design/docker-lan-v1.md §10 P2).
PG_RESTORE_CMD = (
    "docker",
    "compose",
    "exec",
    "-T",
    "database",
    "pg_restore",
    "-U",
    "etis",
    "-d",
    "etis",
    "--clean",
    "--if-exists",
    "--no-owner",
    "--no-privileges",
    "--single-transaction",
    "--exit-on-error",
)

MIGRATE_CMD = (
    "docker",
    "compose",
    "run",
    "--rm",
    "migrate",
)


def restore_backup(
    dump_path: Path,
    *,
    root: Path = ROOT,
    runner=subprocess.run,
) -> dict[str, object]:
    if not dump_path.is_file():
        raise FileNotFoundError("backup_dump_missing")
    dump_bytes = dump_path.read_bytes()
    if len(dump_bytes) == 0:
        raise ValueError("backup_dump_empty")

    manifest_path = dump_path.with_name(dump_path.name + ".manifest.json")
    if not manifest_path.is_file():
        raise FileNotFoundError("backup_manifest_missing")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_sha256 = str(manifest.get("dump_sha256", "")).strip()
    actual_sha256 = hashlib.sha256(dump_bytes).hexdigest()
    if not expected_sha256 or not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ValueError("backup_checksum_mismatch")

    env_map = read_env_map(root / ".env")
    current_fp = server_ref_key_fingerprint(env_map.get("ETIS_SERVER_REF_KEY", ""))
    expected_fp = str(manifest.get("server_ref_key_fingerprint", "")).strip()
    if not expected_fp or not hmac.compare_digest(current_fp, expected_fp):
        raise ValueError("server_ref_key_mismatch")

    stop_proc = runner(list(STOP_WRITERS_CMD), cwd=root, capture_output=True, check=False)
    if stop_proc.returncode != 0:
        raise RuntimeError("stop_writers_failed")

    restore_proc = runner(
        list(PG_RESTORE_CMD),
        cwd=root,
        input=dump_bytes,
        capture_output=True,
        check=False,
    )
    if restore_proc.returncode != 0:
        raise RuntimeError("pg_restore_failed")

    migrate_proc = runner(list(MIGRATE_CMD), cwd=root, capture_output=True, check=False)
    if migrate_proc.returncode != 0:
        raise RuntimeError("post_restore_migrate_failed")

    return {
        "restored": True,
        "dump_path": str(dump_path),
        "dump_sha256": actual_sha256,
        "server_ref_key_fingerprint": current_fp,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Restore a PostgreSQL LAN server backup after verifying ETIS_SERVER_REF_KEY")
    p.add_argument("dump_file", type=Path, help="Path to etis-db-YYYYMMDDTHHMMSSZ.dump")
    args = p.parse_args()
    summary = restore_backup(args.dump_file)
    print(json.dumps(summary))
