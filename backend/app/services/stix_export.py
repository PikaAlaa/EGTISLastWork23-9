"""STIX 2.1 pattern and object builders for the offline export (design core-v2 §1, step 3).

Pure functions: no database, no file and no network access. The export command (step 4)
maps rows to these builders, applies the licence filter (§1.4) and writes the bundle.

Rules this module keeps:

- Patterns hold **real, canonical** values (§1.5). A value that is not canonical, such as a
  de-fanged one, is refused rather than exported.
- No `confidence` property is ever written: ETIS confidence is categorical and goes in
  `x_etis_confidence` (§1.2).
- Every object except the TLP marking definitions carries `created_by_ref` (the ETIS
  identity, except on the identity itself) and `object_marking_refs` (one TLP 1.0 marking).
- SDO and SRO ids are UUIDv5 in a per-installation namespace (§1.6). The spec says SDOs
  SHOULD use UUIDv4 and that other versions must avoid collisions; the per-installation
  namespace does that, and the SCO namespace is refused. Bundle ids are UUIDv4.
- Phone indicators have no pattern: STIX 2.1 has no telephone observable (§1.3).

The verified rules are recorded, with their sources, in
`app/resources/stix21-subset-v1.json`; `validate_object` checks every built object against
that subset.
"""
from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.core.indicators import normalize

SUBSET_PATH = Path(__file__).resolve().parents[1] / 'resources' / 'stix21-subset-v1.json'
SUBSET = json.loads(SUBSET_PATH.read_text(encoding='utf-8'))
SPEC_VERSION = SUBSET['spec_version']
SCO_NAMESPACE = uuid.UUID(SUBSET['sco_uuid5_namespace_forbidden_for_sdos'])
TLP = {name: SUBSET['tlp_1_0'][name] for name in ('white', 'green', 'amber', 'red')}
TLP_CREATED = SUBSET['tlp_1_0']['created']
IDENTITY_NAME = 'ETIS local instance'
IDENTITY_CREATED = '2026-11-27T00:00:00.000Z'
INCIDENT_DESCRIPTION = 'Exported from ETIS. Status and severity are ETIS categories.'
ATTACK_NOTICE = ('Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered '
                 'trademarks of The MITRE Corporation.')
HASH_NAMES = {'sha256': 'SHA-256', 'sha1': 'SHA-1', 'md5': 'MD5'}
RELATIONSHIP_TYPES = frozenset({'related-to', 'indicates'})

_ID = re.compile(SUBSET['id_pattern'])
_TS = re.compile(SUBSET['timestamp_pattern_ms'])
_CUSTOM = re.compile(SUBSET['etis_custom_property_pattern'])
_COMMON = ('type', 'spec_version', 'id', 'created', 'modified', 'created_by_ref', 'object_marking_refs',
           'external_references')
# STIX properties each builder may write; anything else must be an `x_etis_*` property.
_ALLOWED = {
    'identity': {'name', 'identity_class'},
    'incident': {'name', 'description'},
    'indicator': {'name', 'pattern', 'pattern_type', 'valid_from', 'indicator_types'},
    'sighting': {'sighting_of_ref', 'first_seen', 'last_seen', 'count', 'where_sighted_refs'},
    'attack-pattern': {'name'},
    'relationship': {'relationship_type', 'source_ref', 'target_ref'},
    'note': {'content', 'object_refs', 'abstract'},
    'marking-definition': {'name', 'definition', 'definition_type'},
}


class StixExportError(ValueError):
    """Raised with a fixed reason code; never carries indicator values."""


# ---------------------------------------------------------------- ids and timestamps

def namespace_from(value: str | uuid.UUID) -> uuid.UUID:
    """Validate the per-installation `ETIS_STIX_NAMESPACE` UUID."""
    try:
        namespace = value if isinstance(value, uuid.UUID) else uuid.UUID(str(value).strip())
    except (ValueError, AttributeError):
        raise StixExportError('stix_namespace_invalid') from None
    if namespace == SCO_NAMESPACE or namespace.int == 0:
        raise StixExportError('stix_namespace_invalid')
    return namespace


def object_id(stix_type: str, namespace: uuid.UUID, key: str) -> str:
    """Deterministic `type--UUIDv5` id over a local key such as `incidents:12`."""
    return f'{stix_type}--{uuid.uuid5(namespace_from(namespace), f"{stix_type}:{key}")}'


def bundle_id() -> str:
    return f'bundle--{uuid.uuid4()}'


def timestamp(value: datetime) -> str:
    """RFC 3339 UTC with a `Z` suffix and millisecond precision. Naive values are UTC (as stored)."""
    if not isinstance(value, datetime):
        raise StixExportError('timestamp_invalid')
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.strftime('%Y-%m-%dT%H:%M:%S.') + f'{value.microsecond // 1000:03d}Z'


# ---------------------------------------------------------------- patterns

def escape_literal(value: str) -> str:
    """STIX pattern string literal body: backslash doubled first, then `'` -> `\\'`."""
    return value.replace('\\', '\\\\').replace("'", "\\'")


def _canonical(kind: str, value: str, hash_algo: str | None) -> str:
    try:
        normalized = normalize(kind, value, hash_algo)
    except ValueError:
        raise StixExportError('value_not_canonical') from None
    if normalized.value != value:
        raise StixExportError('value_not_canonical')
    return value


def pattern_for(kind: str, value: str, hash_algo: str | None = None) -> str | None:
    """STIX pattern for one canonical indicator value, or None for a phone number."""
    if kind == 'phone':
        return None
    if kind not in ('url', 'domain', 'ip', 'email', 'hash'):
        raise StixExportError('indicator_type_unsupported')
    value = _canonical(kind, value, hash_algo if kind == 'hash' else None)
    literal = escape_literal(value)
    if kind == 'url':
        return f"[url:value = '{literal}']"
    if kind == 'domain':
        return f"[domain-name:value = '{literal}']"
    if kind == 'email':
        return f"[email-addr:value = '{literal}']"
    if kind == 'ip':
        family = 'ipv4-addr' if ipaddress.ip_address(value).version == 4 else 'ipv6-addr'
        return f"[{family}:value = '{literal}']"
    name = HASH_NAMES[hash_algo]
    key = f"'{name}'" if '-' in name else name
    return f"[file:hashes.{key} = '{literal}']"


# ---------------------------------------------------------------- objects

def tlp_marking(level: str) -> dict:
    """The predefined TLP 1.0 marking definition (fixed id and created)."""
    if level not in TLP:
        raise StixExportError('tlp_level_unsupported')
    return {'type': 'marking-definition', 'spec_version': SPEC_VERSION, 'id': TLP[level],
            'created': TLP_CREATED, 'definition_type': 'tlp', 'name': f'TLP:{level.upper()}',
            'definition': {'tlp': level}}


def _base(stix_type: str, oid: str, created: str, modified: str, identity_ref: str | None, tlp: str) -> dict:
    if tlp not in TLP:
        raise StixExportError('tlp_level_unsupported')
    if modified < created:
        modified = created
    obj = {'type': stix_type, 'spec_version': SPEC_VERSION, 'id': oid, 'created': created, 'modified': modified}
    if identity_ref:
        obj['created_by_ref'] = identity_ref
    obj['object_marking_refs'] = [TLP[tlp]]
    return obj


def _custom(obj: dict, props: dict) -> dict:
    for key, value in props.items():
        if value is None or value == [] or value == {}:
            continue
        if not _CUSTOM.match(key):
            raise StixExportError('custom_property_name_invalid')
        obj[key] = value
    return obj


def identity(namespace: uuid.UUID, *, tlp: str) -> dict:
    oid = object_id('identity', namespace, 'etis')
    obj = _base('identity', oid, IDENTITY_CREATED, IDENTITY_CREATED, None, tlp)
    obj.update(name=IDENTITY_NAME, identity_class='system')
    return obj


def incident(namespace: uuid.UUID, *, incident_id: int, title: str, opened_at: datetime,
             last_activity_at: datetime, identity_ref: str, tlp: str, custom: dict | None = None) -> dict:
    obj = _base('incident', object_id('incident', namespace, f'incidents:{incident_id}'),
                timestamp(opened_at), timestamp(last_activity_at), identity_ref, tlp)
    obj.update(name=title, description=INCIDENT_DESCRIPTION)
    return _custom(obj, custom or {})


def indicator(namespace: uuid.UUID, *, indicator_id: int, kind: str, value: str, first_seen: datetime,
              identity_ref: str, tlp: str, sources: list[str], hash_algo: str | None = None,
              created: datetime | None = None) -> dict | None:
    """One indicator with a real-value pattern; None for a phone number (no pattern exists)."""
    pattern = pattern_for(kind, value, hash_algo)
    if pattern is None:
        return None
    if not sources:
        raise StixExportError('indicator_sources_required')
    stamp = timestamp(created or first_seen)
    obj = _base('indicator', object_id('indicator', namespace, f'indicators:{indicator_id}'),
                stamp, stamp, identity_ref, tlp)
    obj.update(pattern=pattern, pattern_type='stix', valid_from=timestamp(first_seen),
               indicator_types=['malicious-activity'])
    return _custom(obj, {'x_etis_type': kind, 'x_etis_sources': sorted(set(sources))})


def sighting(namespace: uuid.UUID, *, finding_id: str, indicator_ref: str, observed_at: datetime,
             identity_ref: str, tlp: str, custom: dict | None = None) -> dict:
    stamp = timestamp(observed_at)
    obj = _base('sighting', object_id('sighting', namespace, f'finding_indicators:{finding_id}:{indicator_ref}'),
                stamp, stamp, identity_ref, tlp)
    obj.update(sighting_of_ref=indicator_ref, first_seen=stamp, last_seen=stamp, count=1,
               where_sighted_refs=[identity_ref])
    return _custom(obj, {'x_etis_finding_id': finding_id, **(custom or {})})


def attack_pattern(namespace: uuid.UUID, *, technique_id: str, matrix: str, attack_version: str, name: str,
                   url: str | None, mitre_stix_id: str | None, identity_ref: str, tlp: str,
                   created: datetime) -> dict:
    """An ETIS-made reference to an ATT&CK technique.

    Its id is in the ETIS namespace, not MITRE's `stix_id`: ETIS does not store MITRE's own
    `created`/`modified`, and re-publishing MITRE's id with ETIS timestamps and markings would
    be a conflicting version of MITRE's object. Consumers match it by the `mitre-attack`
    external reference; MITRE's id is kept in `x_etis_mitre_stix_id`.
    """
    stamp = timestamp(created)
    oid = object_id('attack-pattern', namespace, f'attack:{matrix}:{attack_version}:{technique_id}')
    obj = _base('attack-pattern', oid, stamp, stamp, identity_ref, tlp)
    reference = {'source_name': 'mitre-attack', 'external_id': technique_id}
    if url:
        reference['url'] = url
    obj.update(name=name, external_references=[reference])
    return _custom(obj, {'x_etis_mitre_stix_id': mitre_stix_id, 'x_etis_attack_matrix': matrix,
                         'x_etis_attack_version': attack_version})


def relationship(namespace: uuid.UUID, *, relationship_type: str, source_ref: str, target_ref: str,
                 identity_ref: str, tlp: str, created: datetime, custom: dict | None = None) -> dict:
    if relationship_type not in RELATIONSHIP_TYPES:
        raise StixExportError('relationship_type_unsupported')
    stamp = timestamp(created)
    oid = object_id('relationship', namespace, f'{relationship_type}:{source_ref}:{target_ref}')
    obj = _base('relationship', oid, stamp, stamp, identity_ref, tlp)
    obj.update(relationship_type=relationship_type, source_ref=source_ref, target_ref=target_ref)
    return _custom(obj, custom or {})


def note(namespace: uuid.UUID, *, key: str, content: str, object_refs: list[str], identity_ref: str,
         tlp: str, created: datetime, abstract: str | None = None) -> dict:
    if not content or not object_refs:
        raise StixExportError('note_content_and_refs_required')
    stamp = timestamp(created)
    obj = _base('note', object_id('note', namespace, f'note:{key}'), stamp, stamp, identity_ref, tlp)
    obj.update(content=content, object_refs=sorted(set(object_refs)))
    if abstract:
        obj['abstract'] = abstract
    return obj


def bundle(objects: list[dict], *, bundle_ref: str | None = None) -> dict:
    """Bundle with objects sorted by type, then id. 2.1 bundles carry no spec_version."""
    if not objects:
        raise StixExportError('bundle_empty')
    unique = {o['id']: o for o in objects}
    if len(unique) != len(objects):
        raise StixExportError('duplicate_object_id')
    ordered = sorted(objects, key=lambda o: (o['type'], o['id']))
    return {'type': 'bundle', 'id': bundle_ref or bundle_id(), 'objects': ordered}


# ---------------------------------------------------------------- validation against the subset

def _walk_empty(value) -> bool:
    if value == [] or value == {}:
        return True
    if isinstance(value, dict):
        return any(_walk_empty(v) for v in value.values())
    if isinstance(value, list):
        return any(_walk_empty(v) for v in value)
    return False


def validate_object(obj: dict) -> list[str]:
    """Problems found in one object against `stix21-subset-v1` and ETIS rules ([] when valid)."""
    problems = []
    stix_type = obj.get('type')
    rules = SUBSET['types'].get(stix_type)
    if rules is None:
        return ['type_not_in_subset']
    required = rules['required'] + ([] if rules.get('no_common_required') else SUBSET['common_required'])
    problems += [f'missing:{name}' for name in required if name not in obj]
    if obj.get('spec_version') != SPEC_VERSION:
        problems.append('spec_version')
    oid = obj.get('id', '')
    if not _ID.match(oid) or not oid.startswith(f'{stix_type}--'):
        problems.append('id_format')
    for name in rules['timestamps']:
        if name in obj and not _TS.match(obj[name]):
            problems.append(f'timestamp:{name}')
    if 'created' in obj and 'modified' in obj and obj['modified'] < obj['created']:
        problems.append('modified_before_created')
    allowed = set(_COMMON) | _ALLOWED[stix_type]
    for key in obj:
        if key in SUBSET['reserved_property_names']:
            problems.append(f'reserved:{key}')
        elif key not in allowed and not _CUSTOM.match(key):
            problems.append(f'property:{key}')
    if 'confidence' in obj:
        problems.append('confidence_forbidden')
    if _walk_empty(obj):
        problems.append('empty_list_or_dict')
    for key, value in obj.items():
        refs = value if key.endswith('_refs') else [value] if key.endswith('_ref') else []
        if any(not isinstance(r, str) or not _ID.match(r) for r in refs):
            problems.append(f'ref:{key}')
    if stix_type == 'marking-definition':
        if oid not in TLP.values() or obj.get('created') != TLP_CREATED or obj.get('definition_type') != 'tlp':
            problems.append('tlp_marking_not_predefined')
    else:
        markings = obj.get('object_marking_refs') or []
        if len(markings) != 1 or markings[0] not in TLP.values():
            problems.append('tlp_marking_missing')
    vocab = SUBSET['vocabularies']
    if stix_type == 'identity' and obj.get('identity_class') not in vocab['identity_class']:
        problems.append('vocab:identity_class')
    if stix_type == 'indicator':
        if obj.get('pattern_type') not in vocab['pattern_type']:
            problems.append('vocab:pattern_type')
        if any(t not in vocab['indicator_types'] for t in obj.get('indicator_types', [])):
            problems.append('vocab:indicator_types')
    if stix_type == 'sighting':
        low, high = SUBSET['sighting_count_range']
        if not isinstance(obj.get('count', 0), int) or not low <= obj.get('count', 0) <= high:
            problems.append('sighting_count')
        where = re.compile(SUBSET['sighting_where_sighted_ref_pattern'])
        if any(not where.match(r) for r in obj.get('where_sighted_refs', [])):
            problems.append('where_sighted_refs')
        if obj.get('last_seen', '') < obj.get('first_seen', ''):
            problems.append('last_seen_before_first_seen')
    if stix_type == 'relationship' and obj.get('relationship_type') not in RELATIONSHIP_TYPES:
        problems.append('relationship_type')
    return problems


def validate_bundle(data: dict) -> list[str]:
    problems = [f'bundle_missing:{n}' for n in SUBSET['bundle']['required'] if n not in data]
    problems += [f'bundle_forbidden:{n}' for n in SUBSET['bundle']['forbidden'] if n in data]
    if data.get('type') != 'bundle' or not _ID.match(data.get('id', '')) or not data.get('id', '').startswith('bundle--'):
        problems.append('bundle_id')
    ids = [o.get('id') for o in data.get('objects', [])]
    if len(ids) != len(set(ids)):
        problems.append('duplicate_object_id')
    known = set(ids)
    for obj in data.get('objects', []):
        problems += [f"{obj.get('id')}:{p}" for p in validate_object(obj)]
        for key, value in obj.items():
            refs = value if key.endswith('_refs') else [value] if key.endswith('_ref') else []
            problems += [f"{obj.get('id')}:dangling:{key}" for r in refs if r not in known]
    return problems
