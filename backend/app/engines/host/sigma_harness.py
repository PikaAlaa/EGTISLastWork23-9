"""Sigma evaluation harness on in-memory SQLite (design host-engine-v1 §2.2-2.3, §4.2, §5.2).

Rules are parsed with pySigma (LGPL-2.1) and converted to SQLite queries with the pinned
SigmaHQ sqlite backend (LGPL-3.0) through the SigmaHQ Windows pipelines (LGPL-2.1), all
used unmodified as installed dependencies. Rule files are never modified: a rule is
included or excluded whole, and every exclusion is counted with a reason code.

ATT&CK tags are resolved against the pinned local v20.0 catalogue: revoked ids follow
their `revoked-by` relationships; unknown, deprecated or unresolvable ids are dropped.
Nothing here downloads, resolves or contacts anything.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from app.core.settings import PROJECT_ROOT
from app.engines.host.coverage import KNOWN_CHANNELS, SECURITY, SYSMON
from app.engines.host.detections import Alert
from app.engines.host.pseudonyms import Pseudonymizer
from app.engines.host.reader import event_table

logger = logging.getLogger(__name__)

LICENSE = 'DRL-1.1'
SOURCE_URL = 'https://github.com/SigmaHQ/sigma/blob/{release}/{path}'
ACCEPTED_STATUS = frozenset({'stable', 'test'})
ACCEPTED_LEVELS = frozenset({'medium', 'high', 'critical'})
# Design §5.1 including amendment 1.
TARGET_TECHNIQUES = frozenset({
    'T1110.001', 'T1110.003', 'T1136.001', 'T1098.007', 'T1059.001', 'T1027.010', 'T1105', 'T1543.003',
    'T1053.005', 'T1685.005', 'T1685.001', 'T1133', 'T1021.001', 'T1685', 'T1078.003', 'T1204.002',
    'T1059.003', 'T1059.005', 'T1218.005', 'T1490', 'T1134.002', 'T1078'})
_TECHNIQUE_TAG = re.compile(r'^t\d{4}(\.\d{3})?$')
_MISSING_COLUMN = re.compile(r'no such column: (.+)$')
# Plain Windows event field names only; dotted paths (e.g. shipper JSON paths) are never produced
# by the EVTX normaliser, so rules naming them are excluded.
SIGMA_FIELD = re.compile(r'^[A-Za-z][A-Za-z0-9_]{0,127}$')
MAX_ADDED_COLUMNS = 64


@dataclass(frozen=True)
class RuleFile:
    path: str  # path inside the pinned release package, '/'-separated
    text: str
    sha256: str


@dataclass(frozen=True)
class Candidate:
    rule_id: str
    title: str
    author: str
    level: str
    status: str
    path: str
    sha256: str
    techniques: tuple[str, ...]
    queries: tuple[str, ...]
    fields: tuple[str, ...]  # columns the queries need beyond the reader's system fields
    release: str


@dataclass
class Selection:
    release_tag: str
    candidates: list[Candidate] = field(default_factory=list)
    excluded: Counter = field(default_factory=Counter)
    excluded_rules: list[tuple[str, str]] = field(default_factory=list)


class TechniqueRemap:
    """Active technique ids and revoked -> replacement mapping from STIX objects."""

    def __init__(self, active: set[str], revoked_by: dict[str, str]):
        self.active, self.revoked_by = frozenset(active), dict(revoked_by)

    @classmethod
    def from_objects(cls, objects: list[dict]) -> 'TechniqueRemap':
        ids, active, revoked = {}, set(), set()
        for obj in objects:
            if obj.get('type') != 'attack-pattern':
                continue
            ref = next((r for r in obj.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)
            if not ref or not ref.get('external_id'):
                continue
            ids[obj['id']] = ref['external_id']
            if obj.get('revoked'):
                revoked.add(ref['external_id'])
            elif not obj.get('x_mitre_deprecated'):
                active.add(ref['external_id'])
        mapping = {}
        for obj in objects:
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'revoked-by':
                source, target = ids.get(obj.get('source_ref')), ids.get(obj.get('target_ref'))
                if source in revoked and target:
                    mapping[source] = target
        return cls(active, mapping)

    def resolve(self, technique_id: str) -> str | None:
        seen, current = set(), technique_id.upper()
        while current not in self.active:
            if current in seen or current not in self.revoked_by:
                return None
            seen.add(current)
            current = self.revoked_by[current]
        return current


def load_remap(lock_path: Path | None = None, root: Path = PROJECT_ROOT) -> TechniqueRemap:
    """Build the remap from the pinned local Enterprise catalogue (data/attack-lock.json)."""
    lock_path = lock_path or (PROJECT_ROOT / 'data' / 'attack-lock.json')
    lock = json.loads(Path(lock_path).read_text(encoding='utf-8'))
    entry = next(f for f in lock['files'] if f['collection'] == 'enterprise')
    path = Path(root) / lock['destination'] / entry['file']
    if not path.is_file():
        raise FileNotFoundError('attack_catalogue_not_installed')
    body = path.read_bytes()
    if len(body) != entry['size'] or hashlib.sha256(body).hexdigest() != entry['sha256']:
        raise ValueError('attack_catalogue_hash_mismatch')
    return TechniqueRemap.from_objects(json.loads(body)['objects'])


def _long(path: Path) -> Path:
    text = str(Path(path).resolve())
    if os.name == 'nt' and not text.startswith('\\\\?\\'):
        text = '\\\\?\\' + text  # deeply nested rule paths exceed 260 characters
    return Path(text)


def load_release(lock_path: Path | None = None, root: Path = PROJECT_ROOT) -> tuple[str, list[RuleFile]]:
    """Read the pinned, extracted SigmaHQ rule files (data/sigma-lock.json); verify the tree hash."""
    lock_path = lock_path or (PROJECT_ROOT / 'data' / 'sigma-lock.json')
    lock = json.loads(Path(lock_path).read_text(encoding='utf-8'))
    expected = lock['extracted']
    base = Path(root) / lock['destination'] / expected['directory']
    if not base.is_dir():
        raise FileNotFoundError('sigma_rules_missing')
    base = _long(base)
    files, lines = [], []
    for path in sorted(base.rglob('*.yml')):
        if not path.is_file():
            continue
        body = path.read_bytes()
        relative, digest = path.relative_to(base).as_posix(), hashlib.sha256(body).hexdigest()
        lines.append(f'{relative}\t{digest}')
        files.append(RuleFile(path=relative, text=body.decode('utf-8', errors='replace'), sha256=digest))
    tree = hashlib.sha256(('\n'.join(sorted(lines)) + '\n').encode('utf-8')).hexdigest()
    if tree != expected['tree_sha256'] or len(files) != expected['rule_files']:
        raise ValueError('sigma_rules_hash_mismatch')
    return lock['release'], sorted(files, key=lambda f: f.path)


def regexp(pattern, value) -> bool:
    """SQLite REGEXP(pattern, value): search semantics; NULLs and invalid patterns never match."""
    if value is None or pattern is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def _pipelines():
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.pipelines.windows import windows_audit_pipeline, windows_logsource_pipeline
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation
    etis = ProcessingPipeline(name='ETIS normalised field names', priority=100, items=[ProcessingItem(
        identifier='etis_provider_name', transformation=FieldMappingTransformation({'Provider_Name': 'Provider'}))])
    return (sysmon_pipeline() + windows_logsource_pipeline() + etis,
            windows_audit_pipeline() + windows_logsource_pipeline() + etis)


def _channels(logsource) -> set[str]:
    """Channels a Windows rule's log source reads, from the pipelines' own mappings."""
    from sigma.pipelines.common import windows_logsource_mapping
    from sigma.pipelines.sysmon.sysmon import sysmon_generic_logsource_eventid_mapping
    from sigma.pipelines.windows.windows import windows_generic_category_channel_mapping
    if (logsource.product or '').lower() != 'windows':
        return set()
    channels: set[str] = set()

    def add(service):
        source = windows_logsource_mapping.get(service)
        channels.update(source if isinstance(source, list) else [source] if source else [])
    if logsource.service:
        add(logsource.service)
    elif logsource.category in windows_generic_category_channel_mapping:
        add(windows_generic_category_channel_mapping[logsource.category]['service'])
    elif logsource.category in sysmon_generic_logsource_eventid_mapping:
        channels.add(SYSMON)
        if logsource.category == 'process_creation':
            channels.add(SECURITY)
    return channels


def _probe(queries: list[str]) -> tuple[str, ...] | None:
    """Run queries on an empty table, adding the columns they name; None if a name is unusable."""
    added: list[str] = []
    with event_table([]) as table:
        table.connection.create_function('REGEXP', 2, regexp, deterministic=True)
        for query in queries:
            for _ in range(MAX_ADDED_COLUMNS + 1):
                try:
                    table.connection.execute(query).fetchall()
                    break
                except sqlite3.OperationalError as exc:
                    missing = _MISSING_COLUMN.search(str(exc))
                    name = missing.group(1).strip('"`') if missing else None
                    if not name or not SIGMA_FIELD.match(name) or len(added) >= MAX_ADDED_COLUMNS:
                        return None
                    table.connection.execute(f'ALTER TABLE logs ADD COLUMN "{name}" TEXT COLLATE NOCASE')
                    added.append(name)
            else:
                return None
    return tuple(added)


def _is_correlation(text: str) -> bool:
    """Correlation rules (event_count, value_count, temporal) are excluded before resolution."""
    import yaml
    try:
        return any(isinstance(doc, dict) and 'correlation' in doc for doc in yaml.safe_load_all(text))
    except yaml.YAMLError:
        return False


def _exclude(selection: Selection, path: str, reason: str) -> None:
    selection.excluded[reason] += 1
    selection.excluded_rules.append((path, reason))


def build_candidates(rule_files: list[RuleFile], remap: TechniqueRemap, release_tag: str,
                     target: frozenset = TARGET_TECHNIQUES) -> Selection:
    """Apply the fixed candidate-pool filters of design §4.2 to unmodified rule files."""
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule
    default, audit = _pipelines()
    selection = Selection(release_tag=release_tag)
    for item in rule_files:
        if _is_correlation(item.text):
            _exclude(selection, item.path, 'correlation')
            continue
        try:
            collection = SigmaCollection.from_yaml(item.text)
            rules = list(collection.rules)
        except Exception:  # noqa: BLE001 - any parse failure excludes the whole rule
            _exclude(selection, item.path, 'conversion_failed')
            continue
        if len(rules) != 1:
            _exclude(selection, item.path, 'conversion_failed')
            continue
        rule = rules[0]
        if not isinstance(rule, SigmaRule):
            _exclude(selection, item.path, 'correlation')
            continue
        channels = _channels(rule.logsource)
        if not channels & set(KNOWN_CHANNELS):
            _exclude(selection, item.path, 'logsource')
            continue
        status = str(rule.status).lower() if rule.status else ''
        if status not in ACCEPTED_STATUS:
            _exclude(selection, item.path, 'status')
            continue
        level = str(rule.level).lower() if rule.level else ''
        if level not in ACCEPTED_LEVELS:
            _exclude(selection, item.path, 'level')
            continue
        techniques = []
        for tag in rule.tags:
            if tag.namespace == 'attack' and _TECHNIQUE_TAG.match(tag.name.lower()):
                resolved = remap.resolve(tag.name.upper())
                if resolved and resolved in target and resolved not in techniques:
                    techniques.append(resolved)
        if not techniques:
            _exclude(selection, item.path, 'technique')
            continue
        variants = [default] + ([audit] if rule.logsource.category == 'process_creation' else [])
        try:
            queries = []
            for pipeline in variants:
                queries.extend(sqliteBackend(pipeline).convert(SigmaCollection.from_yaml(item.text)))
        except Exception:  # noqa: BLE001 - unsupported features exclude the whole rule
            _exclude(selection, item.path, 'conversion_failed')
            continue
        if not queries or not all(q.startswith('SELECT * FROM logs WHERE ') for q in queries):
            _exclude(selection, item.path, 'conversion_failed')
            continue
        fields = _probe(queries)
        if fields is None:
            _exclude(selection, item.path, 'unsupported_field_name')
            continue
        selection.candidates.append(Candidate(
            rule_id=str(rule.id), title=rule.title, author=rule.author or '', level=level, status=status,
            path=item.path, sha256=item.sha256, techniques=tuple(techniques), queries=tuple(queries), fields=fields,
            release=release_tag))
    return selection


def attribution(candidate: Candidate) -> dict:
    """DRL 1.1: messages based on matches retain the rule's author identification (§2.2)."""
    return {'id': candidate.rule_id, 'title': candidate.title, 'author': candidate.author, 'level': candidate.level,
            'status': candidate.status, 'release': candidate.release, 'path': candidate.path,
            'sha256': candidate.sha256, 'license': LICENSE,
            'source': SOURCE_URL.format(release=candidate.release, path=candidate.path)}


def evaluate(candidates: list[Candidate], records: list[dict], pseudo: Pseudonymizer) -> list[Alert]:
    """Run candidate queries over one import's records; one alert per (rule, matching event)."""
    extra = sorted({name for c in candidates for name in c.fields})
    alerts = []
    with event_table(records, extra_columns=extra) as table:
        table.connection.create_function('REGEXP', 2, regexp, deterministic=True)
        for candidate in candidates:
            rows: set[int] = set()
            for query in candidate.queries:
                selected = query.replace('SELECT * FROM logs', 'SELECT _etis_row FROM logs', 1)
                try:
                    rows.update(row for (row,) in table.connection.execute(selected))
                except sqlite3.Error:
                    logger.warning('host_sigma_query_failed')
            block = attribution(candidate)
            for row in sorted(rows):
                record = records[row - 1]
                alerts.append(Alert(
                    detection='sigma:' + candidate.rule_id, level=candidate.level, techniques=candidate.techniques,
                    start=record['TimeCreated'], end=record['TimeCreated'], record_ids=(record['EventRecordID'],),
                    host_ref=pseudo.host_ref(record.get('Computer')), facts={'sigma': block}))
    return alerts
