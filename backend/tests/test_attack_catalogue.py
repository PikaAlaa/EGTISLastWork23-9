"""ATT&CK catalogue loader and technique validation (design core-v1 §4, §9.8).

Uses the committed v20.0 subset fixture (identifiers/names/tactics only); no network access.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.findings import Finding
from app.models import AttackTechnique, FindingAttack
from app.services.attack import load_catalogue, parse_techniques
from app.services.findings import record_findings

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / 'backend/tests/fixtures/attack-20.0-subset.json').read_text(encoding='utf-8'))
LOCK = json.loads((ROOT / 'data/attack-lock.json').read_text(encoding='utf-8'))


def ids(rows):
    return {row['technique_id'] for row in rows}


def test_fixture_is_traceable_to_the_pinned_files_and_carries_no_descriptions():
    assert FIXTURE['attack_version'] == LOCK['version'] == '20.0'
    assert FIXTURE['copyright_statement'] == LOCK['copyright_statement']
    assert {k: v['sha256'] for k, v in FIXTURE['sources'].items()} == {f['collection']: f['sha256'] for f in LOCK['files']}
    assert 'description' not in json.dumps(FIXTURE['objects'])


def test_parser_skips_revoked_and_deprecated():
    enterprise = parse_techniques(FIXTURE['objects']['enterprise'], 'enterprise', '20.0')
    mobile = parse_techniques(FIXTURE['objects']['mobile'], 'mobile', '20.0')
    assert 'T1656' not in ids(enterprise)  # revoked by T1684.001 in v20.0
    assert 'T1153' not in ids(enterprise) and 'T1470' not in ids(mobile)  # deprecated
    by_id = {row['technique_id']: row for row in enterprise + mobile}
    assert by_id['T1566.004']['name'] == 'Spearphishing Voice'
    assert by_id['T1684.001']['name'] == 'Impersonation' and by_id['T1684.001']['tactics'] == ['stealth']
    assert by_id['T1660']['matrix'] == 'mobile' and by_id['T1660']['tactics'] == ['initial-access']
    assert by_id['T1660']['url'].startswith('https://attack.mitre.org/techniques/T1660')


@pytest.fixture
def local_catalogue(tmp_path):
    """Write fixture objects as bundles plus a lock describing exactly those bytes."""
    destination = tmp_path / 'attack'
    destination.mkdir()
    files = []
    for matrix in ('enterprise', 'mobile'):
        body = json.dumps({'type': 'bundle', 'objects': FIXTURE['objects'][matrix]}).encode('utf-8')
        name = f'{matrix}-attack-20.0.json'
        (destination / name).write_bytes(body)
        files.append(dict(collection=matrix, file=name, size=len(body), sha256=hashlib.sha256(body).hexdigest()))
    lock = dict(version='20.0', destination='attack', files=files)
    lock_path = tmp_path / 'lock.json'
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    return lock_path, tmp_path


def test_loader_is_idempotent(db, local_catalogue):
    lock_path, root = local_catalogue
    first = load_catalogue(db, lock_path, root)
    assert first['enterprise'].startswith('loaded:') and first['mobile'] == 'loaded:2'
    assert load_catalogue(db, lock_path, root) == {'enterprise': 'already_loaded', 'mobile': 'already_loaded'}
    assert db.query(AttackTechnique).filter_by(technique_id='T1656').count() == 0
    assert db.query(AttackTechnique).filter_by(technique_id='T1660', matrix='mobile').count() == 1


def test_missing_files_mean_not_installed(db, local_catalogue):
    lock_path, root = local_catalogue
    for path in (root / 'attack').iterdir():
        path.unlink()
    assert load_catalogue(db, lock_path, root) == {'enterprise': 'not_installed', 'mobile': 'not_installed'}
    assert db.query(AttackTechnique).count() == 0


def test_hash_mismatch_refuses_to_load(db, local_catalogue):
    lock_path, root = local_catalogue
    target = root / 'attack' / 'enterprise-attack-20.0.json'
    body = target.read_bytes()
    target.write_bytes(body.replace(b'Phishing', b'Phishinx', 1))
    with pytest.raises(ValueError, match='attack_catalogue_hash_mismatch:enterprise'):
        load_catalogue(db, lock_path, root)
    assert db.query(AttackTechnique).filter_by(matrix='enterprise').count() == 0


def finding(*techniques):
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    return Finding.model_validate(dict(
        engine={'name': 'phishing.analyze', 'version': 'test'}, domain='phishing', kind='sms_phishing',
        severity='medium', confidence='single_signal',
        attack=[{'technique_id': t, 'matrix': m, 'attack_version': '20.0', 'basis': 'test'} for t, m in techniques],
        observed_at=now, created_at=now, source={'kind': 'scan', 'ref': 'scan_requests:0'}))


def test_unknown_or_revoked_ids_are_rejected_without_logging_values(db, local_catalogue, caplog):
    load_catalogue(db, *local_catalogue)
    f = finding(('T1566', 'enterprise'), ('T1656', 'enterprise'), ('T9999', 'enterprise'), ('T1660', 'mobile'),
                ('T1566', 'mobile'))
    with caplog.at_level(logging.WARNING):
        record_findings(db, [f]); db.commit()
    stored = {(row.technique_id, row.matrix) for row in db.query(FindingAttack).filter_by(finding_id=f.id)}
    assert stored == {('T1566', 'enterprise'), ('T1660', 'mobile')}
    assert [r.getMessage() for r in caplog.records].count('attack_mapping_rejected') == 3
    assert not any('T1656' in r.getMessage() or 'T9999' in r.getMessage() for r in caplog.records)


def test_ids_are_kept_when_catalogue_not_installed(db):
    f = finding(('T1566', 'enterprise'), ('T9999', 'enterprise'))
    record_findings(db, [f]); db.commit()
    assert db.query(FindingAttack).filter_by(finding_id=f.id).count() == 2
