"""Load the pinned local ATT&CK catalogue and validate technique ids (design core-v1 §4.1, §4.2).

Reads only local files under data/external/attack/ that match data/attack-lock.json.
Never downloads anything. If the files are absent the platform still runs: findings
keep their technique ids and the catalogue reports `not_installed`.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from app.core.settings import PROJECT_ROOT
from app.models import AttackTechnique

logger = logging.getLogger(__name__)
LOCK_PATH = PROJECT_ROOT / 'data' / 'attack-lock.json'
SOURCE_NAMES = {'mitre-attack', 'mitre-mobile-attack'}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def parse_techniques(objects: list[dict], matrix: str, version: str) -> list[dict]:
    """Return catalogue rows for attack-patterns that are neither revoked nor deprecated."""
    rows = {}
    for obj in objects:
        if obj.get('type') != 'attack-pattern' or obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        ref = next((r for r in obj.get('external_references', []) if r.get('source_name') in SOURCE_NAMES), None)
        if not ref or not ref.get('external_id'):
            continue
        rows[ref['external_id']] = dict(
            technique_id=ref['external_id'], matrix=matrix, attack_version=version, name=obj['name'][:255],
            tactics=sorted({p['phase_name'] for p in obj.get('kill_chain_phases', [])}),
            platforms=list(obj.get('x_mitre_platforms', [])), stix_id=obj['id'], url=ref.get('url'))
    return list(rows.values())


def load_catalogue(db, lock_path: Path = LOCK_PATH, root: Path = PROJECT_ROOT) -> dict:
    lock = json.loads(lock_path.read_text(encoding='utf-8'))
    version, results = lock['version'], {}
    for entry in lock['files']:
        matrix = entry['collection']
        if db.query(AttackTechnique).filter_by(matrix=matrix, attack_version=version).first():
            results[matrix] = 'already_loaded'
            continue
        path = root / lock['destination'] / entry['file']
        if not path.is_file():
            results[matrix] = 'not_installed'
            continue
        if path.stat().st_size != entry['size'] or _sha256(path) != entry['sha256']:
            raise ValueError(f'attack_catalogue_hash_mismatch:{matrix}')
        objects = json.loads(path.read_text(encoding='utf-8'))['objects']
        rows = parse_techniques(objects, matrix, version)
        db.add_all(AttackTechnique(**row) for row in rows)
        db.commit()
        results[matrix] = f'loaded:{len(rows)}'
    return results


class AttackValidator:
    """Per-call cache: validates (technique, matrix, version) against loaded catalogues only."""

    def __init__(self, db):
        self.db, self._known = db, {}

    def _ids(self, matrix: str, version: str) -> set[str] | None:
        key = (matrix, version)
        if key not in self._known:
            ids = {row.technique_id for row in self.db.query(AttackTechnique.technique_id)
                   .filter_by(matrix=matrix, attack_version=version)}
            self._known[key] = ids or None
        return self._known[key]

    def accept(self, technique_id: str, matrix: str, version: str) -> bool:
        ids = self._ids(matrix, version)
        if ids is None:
            return True  # catalogue not installed: keep the recorded id (§4.1)
        if technique_id in ids:
            return True
        # Fail closed on the mapping only; log a reason code, never input values.
        logger.warning('attack_mapping_rejected')
        return False
