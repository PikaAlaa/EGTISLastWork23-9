"""network.windows step 11: migration 008 and data/scripts/import_network_windows.py (design §1.3, §6, §7).

Every log, list and manifest is invented in tmp_path; the command never reads a real export here.
Sockets are blocked for every test.
"""
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.findings import Finding
from app.core.indicators import sha256_hex
from app.engines.host.pseudonyms import KEY_ENV, Pseudonymizer
from app.engines.network_windows import blocklists
from app.engines.network_windows.engine import NetworkWindowsEngine, verify_manifest
from app.engines.network_windows.store import indicator_domain_hashes
from app.engines.registry import EngineRegistry
from app.models import CorrelationStoplist, FindingRecord, Incident, NetworkWindowsImport
from app.services.findings import record_findings
from malware_fixtures import block_network
from network_windows_fixtures import firewall_line, query_response, write_evtx, write_firewall, write_shipped

ROOT = Path(__file__).resolve().parents[2]
KEY_HEX = '24' * 32
T9 = __import__('datetime').datetime(2026, 1, 5, 9, 0, tzinfo=__import__('datetime').timezone.utc)
C2 = '203.0.113.66'
MARKERS = ('MARKER-PC-4410', 'marker-user-4410', 'marker-query-4410', '192.168.44.10', C2,
           'phish-invented', 'tmp_marker_dir')


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


command = _load('etis_import_network_windows', 'data/scripts/import_network_windows.py')


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    block_network(monkeypatch)
    monkeypatch.delenv(KEY_ENV, raising=False)


def sessions(db):
    return sessionmaker(bind=db.get_bind(), expire_on_commit=False)


def env_file(tmp_path):
    path = tmp_path / 'invented.env'
    path.write_text(f'{KEY_ENV}={KEY_HEX}\n', encoding='utf-8')
    return path


def build_engine(root):
    folder = root / 'data' / 'external' / 'network-blocklists'
    folder.mkdir(parents=True)
    body = f'# invented\n{C2}\n'.encode()
    (folder / 'feodo.txt').write_bytes(body)
    lock = root / 'data' / 'network-blocklists-lock.json'
    lock.write_text(json.dumps({'destination': 'data/external/network-blocklists', 'lists': [{
        'name': 'feodo_tracker', 'url': 'https://feodotracker.abuse.ch/invented.txt',
        'fetched_at': '2026-01-04T00:00:00Z', 'file': 'feodo.txt', 'size': len(body),
        'sha256': hashlib.sha256(body).hexdigest(), 'rows': 1, 'format': 'ip_lines'}]}), encoding='utf-8')
    lists = blocklists.load(lock, root)
    manifest = write_shipped(root, lists=[('feodo_tracker', lists.lock_sha256)])
    return NetworkWindowsEngine(verify_manifest(manifest, root), lists=lists, popular_rank=lambda d: None)


def inputs(tmp_path):
    folder = tmp_path / 'tmp_marker_dir'
    folder.mkdir()
    dns = write_evtx(folder / 'dns.evtx', [
        query_response('login.phish-invented.example', computer='MARKER-PC-4410', results='203.0.113.80;'),
        query_response('marker-query-4410.quiet-invented.example', at=1, computer='MARKER-PC-4410',
                       results='192.168.44.10;'),
    ])
    firewall = write_firewall(folder / 'pfirewall.log', [
        firewall_line(src='192.168.44.10', dst=C2, dport='443'),
        firewall_line(time='10:05:00', src='192.168.44.10', dst='198.51.100.5', dport='443'),
    ])
    return ['--dns-evtx', str(dns), '--firewall-log', str(firewall), '--device-name', 'MARKER-PC-4410',
            '--utc-offset', '+02:00', '--local-net', '192.168.44.0/24']


def run(tmp_path, db, args, engine=None, registry=None, env=True):
    out = io.StringIO()
    code = command.main(args, session_factory=sessions(db), engine=engine, target_registry=registry or EngineRegistry(),
                        out=out, env_file=env_file(tmp_path) if env else tmp_path / 'absent.env')
    return code, out.getvalue()


# ---------------------------------------------------------------- migration

def migrate(db_path, *args):
    env = {**os.environ, 'DATABASE_URL': 'sqlite:///' + db_path.as_posix()}
    return subprocess.run([sys.executable, '-m', 'alembic', *args], cwd=ROOT, env=env, check=True,
                          capture_output=True, text=True)


def table_names(db_path):
    with sqlite3.connect(db_path) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_migration_upgrades_and_downgrades_on_a_scratch_database(tmp_path):
    db_path = tmp_path / 'scratch.db'
    migrate(db_path, 'upgrade', 'head')
    assert 'network_windows_imports' in table_names(db_path)
    metadata = create_engine('sqlite://')
    Base.metadata.create_all(metadata)
    migrated = create_engine('sqlite:///' + db_path.as_posix())
    shape = lambda engine: sorted((c['name'], str(c['type']), bool(c['nullable']))  # noqa: E731
                                  for c in inspect(engine).get_columns('network_windows_imports'))
    assert shape(migrated) == shape(metadata)
    assert {i['name'] for i in inspect(migrated).get_indexes('network_windows_imports')} == {
        'ix_network_windows_imports_started_at'}
    migrated.dispose()
    columns = {c[0] for c in shape(metadata)}
    assert not columns & {'path', 'file_name', 'computer', 'user', 'domain', 'ip', 'query', 'destination'}
    migrate(db_path, 'upgrade', 'head')   # idempotent
    migrate(db_path, 'downgrade', '007_malware_scans')   # explicit: 009 now sits above 008
    tables = table_names(db_path)
    assert 'network_windows_imports' not in tables and 'malware_scans' in tables
    migrate(db_path, 'upgrade', 'head')
    assert 'network_windows_imports' in table_names(db_path)


# ---------------------------------------------------------------- refusals

def test_refuses_without_the_host_key(db, tmp_path):
    code, _ = run(tmp_path, db, ['--dns-evtx', str(tmp_path / 'absent.evtx')], engine=build_engine(tmp_path),
                  env=False)
    assert code == command.EXIT_REFUSED and db.query(NetworkWindowsImport).count() == 0


def test_without_a_verified_manifest_nothing_is_read_registered_or_emitted(db, tmp_path, capsys):
    registry = EngineRegistry()
    code, out = run(tmp_path, db, ['--dns-evtx', str(tmp_path / 'never-read.evtx')], registry=registry)
    assert code == command.EXIT_UNAVAILABLE
    assert '"rules_missing"' in capsys.readouterr().err and out == ''
    assert registry.names() == [] and db.query(NetworkWindowsImport).count() == 0
    assert db.query(FindingRecord).count() == 0


@pytest.mark.parametrize('extra, code', [(['--utc-offset', '2h'], command.EXIT_REFUSED),
                                         (['--local-net', 'not-a-net'], command.EXIT_REFUSED)])
def test_bad_options_are_refused(db, tmp_path, extra, code):
    assert run(tmp_path, db, ['--dns-evtx', 'x.evtx', *extra], engine=build_engine(tmp_path))[0] == code


def test_bad_input_files_are_refused_with_a_reason_code(db, tmp_path, capsys):
    bad = tmp_path / 'bad.evtx'
    bad.write_bytes(b'x' * 5000)
    code, _ = run(tmp_path, db, ['--dns-evtx', str(bad)], engine=build_engine(tmp_path))
    assert code == command.EXIT_REFUSED and 'dns_client_evtx_corrupt' in capsys.readouterr().err
    assert db.query(NetworkWindowsImport).count() == 0


def test_a_command_line_without_inputs_is_rejected():
    with pytest.raises(SystemExit):
        command.parse_args([])


# ---------------------------------------------------------------- an import

def test_import_records_findings_and_one_row_of_counts(db, tmp_path):
    seeded = Finding.model_validate(dict(
        engine={'name': 'phishing.analyze', 'version': 'invented-1'}, domain='phishing', kind='phishing_url',
        severity='high', confidence='corroborated',
        indicators=[{'type': 'domain', 'value_hash': sha256_hex('phish-invented.example'),
                     'value': 'phish-invented.example', 'role': 'link_host'}],
        observed_at=T9, created_at=T9,
        source={'kind': 'scan', 'ref': 'scan_requests:1'}))
    (phish,) = record_findings(db, [seeded])
    db.commit()
    engine, registry = build_engine(tmp_path), EngineRegistry()
    code, out = run(tmp_path, db, inputs(tmp_path), engine=engine, registry=registry)
    assert code == command.EXIT_OK and registry.names() == ['network.windows']
    row = db.query(NetworkWindowsImport).one()
    records = db.query(FindingRecord).filter_by(engine_name='network.windows').all()
    kinds = sorted(r.kind for r in records)
    assert kinds == ['known_bad_destination', 'phishing_domain_lookup'], out
    assert row.findings_by_kind == {'known_bad_destination': 1, 'phishing_domain_lookup': 1}
    assert all(r.source_ref == f'network_windows_imports:{row.id}' and r.source_kind == 'import' for r in records)
    n3 = next(r for r in records if r.kind == 'phishing_domain_lookup')
    assert n3.incident_id == phish.incident_id is not None
    n1 = next(r for r in records if r.kind == 'known_bad_destination')
    assert n1.severity == 'high' and n1.incident_id is not None and n1.incident_id != phish.incident_id
    assert row.manifest_sha256 == engine.shipped.sha256 and row.lists_lock_sha256 == engine.lists.lock_sha256
    assert row.engine_version == engine.version and row.span_first is not None and row.finished_at is not None
    assert [f['source'] for f in row.files] == ['dns_client', 'firewall']
    assert row.counts['events'] == {'dns_client:3020': 2, 'firewall:allowed': 2}
    assert row.coverage['detections']['N3'] == 'visible' and 'N2' in row.coverage['not_run']
    assert '"network_windows_import_id"' in out and 'personal data' in out
    for marker in MARKERS:
        assert marker not in out, marker


def test_the_database_holds_no_names_addresses_or_paths(db, tmp_path):
    assert run(tmp_path, db, inputs(tmp_path), engine=build_engine(tmp_path))[0] == command.EXIT_OK
    dump = []
    for table in Base.metadata.sorted_tables:
        dump += [repr(tuple(row)) for row in db.execute(text(f'SELECT * FROM "{table.name}"'))]
    joined = '\n'.join(dump)
    for marker in MARKERS:
        assert marker not in joined, marker
    # Design core-v2 §3.2: only the server-wrapped srv: device_ref is stored, never the endpoint hmac: ref.
    from app.core.device_names import load_server_key, local_device_name, wrap_ref
    endpoint = Pseudonymizer(bytes.fromhex(KEY_HEX)).host_ref(local_device_name('MARKER-PC-4410'))
    assert endpoint not in joined and 'hmac:' not in joined
    assert wrap_ref(endpoint, 'device', load_server_key()) in joined


def test_indicator_store_view_excludes_own_output_and_exclusions(db, tmp_path):
    def seed(engine_name, value, kind='domain'):
        finding = Finding.model_validate(dict(
            engine={'name': engine_name, 'version': 'invented-1'}, domain='network', kind='invented_kind',
            severity='low', confidence='single_signal',
            indicators=[{'type': kind, 'value_hash': sha256_hex(value), 'value': None, 'role': 'resolved_name',
                         **({'registered_domain_hash': sha256_hex(value)} if kind in ('domain', 'url') else {})}],
            observed_at=T9, created_at=T9,
            source={'kind': 'scan', 'ref': 'scan_requests:1'}))
        record_findings(db, [finding])
    seed('phishing.analyze', 'kept-invented.example')
    seed('network.windows', 'own-invented.example')
    seed('phishing.analyze', 'stop-invented.example')
    seed('phishing.analyze', '203.0.113.9', kind='ip')
    db.add(CorrelationStoplist(type='domain', value_hash=sha256_hex('stop-invented.example'), reason='invented'))
    db.commit()
    assert indicator_domain_hashes(db) == frozenset({sha256_hex('kept-invented.example')})


def test_the_command_never_changes_the_system():
    source = (ROOT / 'data/scripts/import_network_windows.py').read_text(encoding='utf-8')
    for forbidden in ('subprocess', 'wevtutil sl', 'netsh', 'Set-NetFirewallProfile', 'schtasks', 'urllib',
                      'requests', 'shutil', 'unlink', 'os.remove', 'write_text', 'write_bytes'):
        assert forbidden not in source, forbidden
