"""Migration 010_agent_devices (design windows-agent-lan-v1 §7.1, §10 step 1).

Fresh database to head and upgrade from 009 with existing rows give the same schema as the models;
re-running is idempotent; downgrade drops only the three agent tables; no existing table changes;
ETIS_SERVER_REF_KEY is generated once by scripts/initialize.py and never overwritten. Each test uses its own
temporary SQLite file. All rows and keys are invented.
"""
import importlib.util
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from app.core.database import Base
import app.models  # noqa: F401  (registers every model)

ROOT = Path(__file__).resolve().parents[2]
AGENT_TABLES = ('devices', 'device_pairing_tokens', 'agent_batches')
STORED_REF = 'srv:' + 'ab' * 16   # invented


def migrate(db_path, *args):
    env = {**os.environ, 'DATABASE_URL': 'sqlite:///' + db_path.as_posix()}
    return subprocess.run([sys.executable, '-m', 'alembic', *args], cwd=ROOT, env=env, check=True,
                          capture_output=True, text=True)


def tables(db_path):
    with sqlite3.connect(db_path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def schema(url_or_engine, table):
    engine = create_engine(url_or_engine) if isinstance(url_or_engine, str) else url_or_engine
    try:
        found = inspect(engine)
        return (sorted((c['name'], str(c['type']), bool(c['nullable'])) for c in found.get_columns(table)),
                sorted((i['name'], tuple(i['column_names']), bool(i['unique'])) for i in found.get_indexes(table)),
                sorted((u['name'], tuple(u['column_names'])) for u in found.get_unique_constraints(table)),
                sorted((tuple(f['constrained_columns']), f['referred_table']) for f in found.get_foreign_keys(table)))
    finally:
        if isinstance(url_or_engine, str):
            engine.dispose()


def all_columns(db_path):
    url = 'sqlite:///' + db_path.as_posix()
    engine = create_engine(url)
    try:
        return {t: sorted((c['name'], str(c['type']), bool(c['nullable'])) for c in inspect(engine).get_columns(t))
                for t in tables(db_path)}
    finally:
        engine.dispose()


def seed_009_rows(db_path):
    """Invented rows in pre-agent tables, including a finding with its stored device."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT INTO findings (id,schema_version,engine_name,engine_version,domain,kind,severity,"
                     "confidence,evidence,observed_at,created_at,source_kind,source_ref) VALUES "
                     "('7c1d6c1e-3f0a-4c55-9a39-1a1d3e1b2c3d','finding-v1','network.windows','invented','network',"
                     "'beaconing','low','single_signal','{}','2026-11-20 00:00:00','2026-11-20 00:00:00','import',"
                     "'network_windows_imports:1')")
        conn.execute("INSERT INTO finding_devices (finding_id,device_ref,attributed_by) VALUES "
                     f"('7c1d6c1e-3f0a-4c55-9a39-1a1d3e1b2c3d','{STORED_REF}','engine_details')")


def database_at_009(db_path):
    """A database as it was before this migration existed. The baseline (001) creates every live model table
    it does not exclude, as for malware_scans and network_windows_imports (007, 008), so the agent tables are
    dropped here to reproduce a pre-agent database."""
    migrate(db_path, 'upgrade', '009_finding_devices')
    with sqlite3.connect(db_path) as conn:
        for table in reversed(AGENT_TABLES):
            conn.execute(f'DROP TABLE IF EXISTS {table}')
    assert not set(AGENT_TABLES) & tables(db_path)


def dump(db_path, table):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()


def test_fresh_and_upgrade_from_009_match_the_models_and_keep_existing_rows(tmp_path):
    fresh, upgraded = tmp_path / 'fresh.db', tmp_path / 'from009.db'
    migrate(fresh, 'upgrade', 'head')
    database_at_009(upgraded)
    seed_009_rows(upgraded)
    before_columns = all_columns(upgraded)
    before_rows = {t: dump(upgraded, t) for t in ('findings', 'finding_devices')}
    migrate(upgraded, 'upgrade', 'head')
    migrate(upgraded, 'upgrade', 'head')   # idempotent re-run
    metadata_engine = create_engine('sqlite://')
    Base.metadata.create_all(metadata_engine)
    for table in AGENT_TABLES:
        expected = schema(metadata_engine, table)
        assert schema('sqlite:///' + fresh.as_posix(), table) == expected, table
        assert schema('sqlite:///' + upgraded.as_posix(), table) == expected, table
    after = all_columns(upgraded)
    assert {t: after[t] for t in before_columns} == before_columns, 'no existing table changes'
    assert {t: dump(upgraded, t) for t in before_rows} == before_rows


def test_agent_schema_column_by_column():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    columns, indexes, uniques, fks = schema(engine, 'devices')
    assert ('device_ref', 'VARCHAR(37)', False) in columns and ('token_hash', 'VARCHAR(64)', True) in columns
    assert ('ix_devices_token_hash', ('token_hash',), True) in indexes
    assert uniques == [('uq_devices_device_ref', ('device_ref',))]
    columns, _, uniques, fks = schema(engine, 'device_pairing_tokens')
    assert ('code_hash', 'VARCHAR(64)', False) in columns and ('failed_attempts', 'INTEGER', False) in columns
    assert uniques == [('uq_device_pairing_tokens_code_hash', ('code_hash',))] and fks == [(('device_id',), 'devices')]
    columns, indexes, uniques, fks = schema(engine, 'agent_batches')
    assert ('ix_agent_batches_received_at', ('received_at',), False) in indexes
    assert uniques == [('uq_agent_batches_device_batch', ('device_id', 'batch_id'))] and fks == [(('device_id',), 'devices')]
    names = {c[0] for c in schema(engine, 'devices')[0]}
    for forbidden in ('hostname', 'computer_name', 'username', 'ip', 'mac', 'token', 'pairing_code'):
        assert forbidden not in names


def test_downgrade_drops_only_agent_tables_and_can_reapply(tmp_path):
    db = tmp_path / 'down.db'
    migrate(db, 'upgrade', 'head')
    seed_009_rows(db)
    before = all_columns(db)
    migrate(db, 'downgrade', '009_finding_devices')
    assert not set(AGENT_TABLES) & tables(db)
    assert {t: c for t, c in before.items() if t not in AGENT_TABLES} == all_columns(db)
    assert dump(db, 'finding_devices') == [('7c1d6c1e-3f0a-4c55-9a39-1a1d3e1b2c3d', STORED_REF, 'engine_details')]
    migrate(db, 'upgrade', 'head')
    assert set(AGENT_TABLES) <= tables(db)


def test_preexisting_agent_table_with_wrong_columns_is_refused(tmp_path):
    db = tmp_path / 'conflict.db'
    database_at_009(db)
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname TEXT)')
    with pytest.raises(subprocess.CalledProcessError) as error:
        migrate(db, 'upgrade', 'head')
    assert 'devices_exists_with_unexpected_columns' in error.value.stderr


def test_initialize_generates_the_server_ref_key_once_and_never_overwrites_it(tmp_path):
    spec = importlib.util.spec_from_file_location('etis_initialize_agent', ROOT / 'scripts' / 'initialize.py')
    initialize = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(initialize)
    env = tmp_path / '.env'
    env.write_text('', encoding='utf-8')
    initialize.ensure_env_secrets(env, template_path=tmp_path / 'absent.example')
    first = [line for line in env.read_text(encoding='utf-8').splitlines() if line.startswith('ETIS_SERVER_REF_KEY=')]
    assert len(first) == 1 and len(bytes.fromhex(first[0].split('=', 1)[1])) == 32
    invented = 'ETIS_SERVER_REF_KEY=' + '7e' * 32
    env.write_text(invented + '\n', encoding='utf-8')
    initialize.ensure_env_secrets(env, template_path=tmp_path / 'absent.example')
    assert invented in env.read_text(encoding='utf-8').splitlines()
