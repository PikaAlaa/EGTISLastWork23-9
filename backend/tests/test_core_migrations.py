"""Core v1 migrations (design core-v1 §7.2, §9.9): fresh vs upgrade schema, idempotence,
downgrade, and no change to any pre-existing table. Each test uses its own temporary SQLite file."""
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
PRE_CORE_HEAD = '003_feed_observations'
CORE_TABLES = {'004_indicators': ['indicators', 'indicator_sightings', 'correlation_stoplist'],
               '005_findings_incidents': ['campaigns', 'incidents', 'findings', 'finding_indicators', 'finding_attack',
                                          'incident_indicators', 'incident_links', 'incident_events']}
ALL_CORE = [t for tables in CORE_TABLES.values() for t in tables]
LEGACY_TABLES = ['blacklist_entries', 'feed_observations', 'feed_snapshots', 'feed_updates', 'scan_requests',
                 'scan_results', 'community_reports', 'egyptian_brands', 'brand_domains']


def migrate(db_path, *args):
    env = {**os.environ, 'DATABASE_URL': 'sqlite:///' + db_path.as_posix()}
    return subprocess.run([sys.executable, '-m', 'alembic', *args], cwd=ROOT, env=env, check=True,
                          capture_output=True, text=True)


def columns(url_or_engine, table):
    engine = create_engine(url_or_engine) if isinstance(url_or_engine, str) else url_or_engine
    try:
        return sorted((c['name'], str(c['type']), bool(c['nullable'])) for c in inspect(engine).get_columns(table))
    finally:
        if isinstance(url_or_engine, str):
            engine.dispose()


def tables(db_path):
    with sqlite3.connect(db_path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def dump(db_path, table):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()


def insert_legacy_rows(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT INTO blacklist_entries (url,url_hash,domain,source,reputation_score,is_active,first_seen,last_seen) "
                     "VALUES ('https://legacy.example/','" + 'b' * 64 + "','legacy.example','openphish',90,1,'2026-10-01','2026-10-02')")
        conn.execute("INSERT INTO feed_observations (url_hash,source,last_seen) VALUES ('" + 'b' * 64 + "','openphish','2026-10-02')")
        conn.execute("INSERT INTO scan_requests (url_hash,text_hash,input_type) VALUES (NULL,'" + 'c' * 64 + "','text')")


def test_fresh_and_upgrade_paths_give_identical_core_schema(tmp_path):
    fresh, upgraded = tmp_path / 'fresh.db', tmp_path / 'upgraded.db'
    migrate(fresh, 'upgrade', 'head')
    migrate(upgraded, 'upgrade', PRE_CORE_HEAD)
    assert not set(ALL_CORE) & tables(upgraded), 'baseline must not create core v1 tables'
    insert_legacy_rows(upgraded)
    before = {t: dump(upgraded, t) for t in ['blacklist_entries', 'feed_observations', 'scan_requests']}
    migrate(upgraded, 'upgrade', 'head')
    migrate(upgraded, 'upgrade', 'head')  # idempotent re-run
    metadata_engine = create_engine('sqlite://')
    Base.metadata.create_all(metadata_engine)
    for table in ALL_CORE:
        expected = columns(metadata_engine, table)
        assert columns('sqlite:///' + fresh.as_posix(), table) == expected, table
        assert columns('sqlite:///' + upgraded.as_posix(), table) == expected, table
    assert {t: dump(upgraded, t) for t in before} == before


def test_existing_tables_are_unchanged_by_core_migrations(tmp_path):
    base, head = tmp_path / 'base.db', tmp_path / 'head.db'
    migrate(base, 'upgrade', PRE_CORE_HEAD)
    migrate(head, 'upgrade', 'head')
    for table in LEGACY_TABLES:
        assert columns('sqlite:///' + base.as_posix(), table) == columns('sqlite:///' + head.as_posix(), table), table


@pytest.mark.parametrize('revision', list(CORE_TABLES))
def test_downgrade_drops_only_its_tables_and_can_reapply(tmp_path, revision):
    db = tmp_path / 'down.db'
    migrate(db, 'upgrade', revision)
    assert set(CORE_TABLES[revision]) <= tables(db)
    migrate(db, 'downgrade', '-1')
    assert not set(CORE_TABLES[revision]) & tables(db)
    assert set(LEGACY_TABLES) <= tables(db)
    migrate(db, 'upgrade', revision)
    assert set(CORE_TABLES[revision]) <= tables(db)


def test_findings_downgrade_refuses_to_lose_analyst_notes(tmp_path):
    db = tmp_path / 'notes.db'
    migrate(db, 'upgrade', '005_findings_incidents')
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO incidents (id,title,domain,severity,status,opened_at,last_activity_at) "
                     "VALUES (1,'t','phishing','high','open','2026-11-18','2026-11-18')")
        conn.execute("INSERT INTO incident_events (incident_id,actor,action,note,at) "
                     "VALUES (1,'local-operator','created','invented note','2026-11-18')")
    with pytest.raises(subprocess.CalledProcessError) as error:
        migrate(db, 'downgrade', '004_indicators')
    assert 'incident_events_not_empty' in error.value.stderr
    assert 'incident_events' in tables(db)
    env = {**os.environ, 'DATABASE_URL': 'sqlite:///' + db.as_posix(), 'ETIS_ALLOW_DESTRUCTIVE_DOWNGRADE': '1'}
    subprocess.run([sys.executable, '-m', 'alembic', 'downgrade', '004_indicators'], cwd=ROOT, env=env, check=True,
                   capture_output=True)
    assert 'incident_events' not in tables(db)


def test_preexisting_table_with_wrong_columns_is_refused(tmp_path):
    db = tmp_path / 'conflict.db'
    migrate(db, 'upgrade', PRE_CORE_HEAD)
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE indicators (id INTEGER PRIMARY KEY, unexpected TEXT)')
    with pytest.raises(subprocess.CalledProcessError) as error:
        migrate(db, 'upgrade', 'head')
    assert 'indicators_exists_with_unexpected_columns' in error.value.stderr
