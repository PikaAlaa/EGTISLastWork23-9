"""Unit tests for PostgreSQL LAN backup, restore, and ETIS_SERVER_REF_KEY fingerprint verification (docker-lan-v1.md §8.4)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import lan_backup, lan_restore  # noqa: E402


def _write_test_env(root: Path, *, server_ref_key: str = "ab" * 32, retention_days: int = 30) -> None:
    (root / ".env").write_text(
        f"ETIS_SERVER_REF_KEY={server_ref_key}\nETIS_RETENTION_DAYS={retention_days}\n",
        encoding="utf-8",
    )


def test_create_backup_writes_dump_and_manifest_with_key_fingerprint(tmp_path: Path) -> None:
    raw_key = "12" * 32
    _write_test_env(tmp_path, server_ref_key=raw_key, retention_days=30)
    fake_dump_bytes = b"PGDMP\x01\x0e\x00custom-dump-payload"
    recorded_cmds: list[list[str]] = []

    def _fake_runner(cmd, cwd=None, capture_output=False, check=False, **kwargs):
        recorded_cmds.append(cmd)
        return SimpleNamespace(returncode=0, stdout=fake_dump_bytes, stderr=b"")

    fixed_now = datetime(2026, 11, 27, 19, 30, 0, tzinfo=timezone.utc)
    result = lan_backup.create_backup(root=tmp_path, runner=_fake_runner, now_utc=fixed_now)

    assert result["backup_created"] is True
    assert recorded_cmds == [list(lan_backup.PG_DUMP_CMD)]

    dump_path = Path(str(result["dump_path"]))
    manifest_path = Path(str(result["manifest_path"]))
    assert dump_path.is_file()
    assert dump_path.read_bytes() == fake_dump_bytes
    assert manifest_path.is_file()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["dump_sha256"] == hashlib.sha256(fake_dump_bytes).hexdigest()
    assert manifest["dump_size_bytes"] == len(fake_dump_bytes)
    assert manifest["server_ref_key_fingerprint"] == lan_backup.server_ref_key_fingerprint(raw_key)
    assert raw_key not in manifest_path.read_text(encoding="utf-8"), "Raw secret key must never appear in manifest"


def test_create_backup_fails_closed_on_missing_key_or_empty_dump(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("ETIS_SERVER_REF_KEY=\n", encoding="utf-8")
    with pytest.raises(ValueError, match="server_ref_key_missing"):
        lan_backup.create_backup(root=tmp_path)

    _write_test_env(tmp_path, server_ref_key="cd" * 32)
    with pytest.raises(RuntimeError, match="empty_or_failed_backup"):
        lan_backup.create_backup(
            root=tmp_path,
            runner=lambda *a, **kw: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
        )
    assert list((tmp_path / "var" / "backups").glob("*.dump")) == []


def test_prune_expired_backups_removes_only_files_older_than_retention(tmp_path: Path) -> None:
    backup_dir = tmp_path / "var" / "backups"
    backup_dir.mkdir(parents=True)

    old_dump = backup_dir / "etis-db-20261001T000000Z.dump"
    old_manifest = backup_dir / "etis-db-20261001T000000Z.dump.manifest.json"
    fresh_dump = backup_dir / "etis-db-20261127T000000Z.dump"
    fresh_manifest = backup_dir / "etis-db-20261127T000000Z.dump.manifest.json"

    for p in (old_dump, old_manifest, fresh_dump, fresh_manifest):
        p.write_bytes(b"test")

    now = time.time()
    old_time = now - (45 * 86400)
    os.utime(old_dump, (old_time, old_time))
    os.utime(old_manifest, (old_time, old_time))

    removed = lan_backup.prune_expired_backups(backup_dir, 30, now=now)
    assert removed == [old_dump.name]
    assert not old_dump.exists() and not old_manifest.exists()
    assert fresh_dump.exists() and fresh_manifest.exists()


def test_restore_backup_verifies_key_fingerprint_and_runs_restore_sequence(tmp_path: Path) -> None:
    raw_key = "ef" * 32
    _write_test_env(tmp_path, server_ref_key=raw_key)
    fake_dump_bytes = b"PGDMP\x01\x0e\x00valid-backup-stream"

    create_res = lan_backup.create_backup(
        root=tmp_path,
        runner=lambda *a, **kw: SimpleNamespace(returncode=0, stdout=fake_dump_bytes, stderr=b""),
        now_utc=datetime(2026, 11, 27, 20, 0, 0, tzinfo=timezone.utc),
    )
    dump_path = Path(str(create_res["dump_path"]))

    restore_calls: list[tuple[list[str], bytes | None]] = []

    def _restore_runner(cmd, cwd=None, input=None, capture_output=False, check=False):
        restore_calls.append((cmd, input))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    restore_res = lan_restore.restore_backup(dump_path, root=tmp_path, runner=_restore_runner)
    assert restore_res["restored"] is True
    assert restore_calls == [
        (list(lan_restore.STOP_WRITERS_CMD), None),
        (list(lan_restore.PG_RESTORE_CMD), fake_dump_bytes),
        (list(lan_restore.MIGRATE_CMD), None),
    ]


def test_restore_backup_refuses_mismatched_server_ref_key_or_corrupted_dump(tmp_path: Path) -> None:
    original_key = "11" * 32
    wrong_key = "22" * 32
    _write_test_env(tmp_path, server_ref_key=original_key)
    fake_dump_bytes = b"PGDMP\x01\x0e\x00valid-backup-stream"

    create_res = lan_backup.create_backup(
        root=tmp_path,
        runner=lambda *a, **kw: SimpleNamespace(returncode=0, stdout=fake_dump_bytes, stderr=b""),
    )
    dump_path = Path(str(create_res["dump_path"]))

    # Change ETIS_SERVER_REF_KEY in .env: restore must fail closed before running any Docker command.
    _write_test_env(tmp_path, server_ref_key=wrong_key)
    called_docker = False

    def _forbid_docker(*args, **kwargs):
        nonlocal called_docker
        called_docker = True
        return SimpleNamespace(returncode=0)

    with pytest.raises(ValueError, match="server_ref_key_mismatch"):
        lan_restore.restore_backup(dump_path, root=tmp_path, runner=_forbid_docker)
    assert called_docker is False

    # Restore original key, then corrupt dump bytes: must fail closed with backup_checksum_mismatch.
    _write_test_env(tmp_path, server_ref_key=original_key)
    dump_path.write_bytes(b"corrupted-bytes")
    with pytest.raises(ValueError, match="backup_checksum_mismatch"):
        lan_restore.restore_backup(dump_path, root=tmp_path, runner=_forbid_docker)
    assert called_docker is False
