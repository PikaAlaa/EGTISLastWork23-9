"""The `network.windows` engine (design network-windows-v1 §4.7, §5, §6).

Turns one pseudonymised import (readers -> devices.pseudonymise) into `finding-v1` Findings.
The caller persists them through the unchanged core `record_findings`; this module never
writes anything.

The engine is usable only with a **verified shipped-item manifest**
(`data/network-windows-shipped.json`, design §4.7): the frozen selection rule it names must
match its SHA-256 and the `FREEZE.json` record, and every shipped rule must repeat the code's
constants exactly. Without one, `health()` reports `rules_missing` with the reason, the
engine is not registrable, `register()` refuses it and `analyze()` emits nothing (it raises).
No manifest is committed: none exists until the owner has frozen the rule, measured and run
the gates (design §9 steps 7-9).

Severity (§6.2), confidence (§6.3), ATT&CK (§5) and indicators (§6.4) are fixed tables.
Destinations and IPs become hash-only indicators; evidence holds numbers, reason codes,
list attribution, coverage states and references only (§6.5, §7).
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from app.core.findings import Finding
from app.core.indicators import normalize_hash, normalize_ip, sha256_hex
from app.engines.network_windows import blocklists as blocklists_module
from app.engines.network_windows import detections
from app.engines.network_windows.devices import coverage_report
from app.engines.network_windows.readers import ReadResult, locality

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[4]
SHIPPED = ROOT / 'data' / 'network-windows-shipped.json'
ENGINE_NAME, DOMAIN = 'network.windows', 'network'
OBSERVATION_KIND = 'windows_network_batch'
SOURCE_PREFIX = 'network_windows_imports:'
MANIFEST_SCHEMA = 'network-windows-shipped-v1'
ATTACK_MATRIX, ATTACK_VERSION = 'enterprise', '20.0'
MAX_INDICATORS = 50
KINDS = {'N1': 'known_bad_destination', 'N2': 'known_bad_destination', 'N3': 'phishing_domain_lookup',
         'N4': 'phishing_domain_lookup', 'N5': 'suspicious_domain', 'N6': 'beaconing', 'N7': 'unusual_port',
         'N8': 'dns_tunnelling_signs', 'N9': 'rare_destination'}
FAMILIES = {'N1': 'lists', 'N2': 'lists', 'N3': 'lists', 'N4': 'model', 'N5': 'lexical', 'N8': 'lexical',
            'N6': 'behavioural', 'N7': 'behavioural', 'N9': 'behavioural'}
VALIDATIONS = ('samples', 'unvalidated_on_samples')
HEALTH_ORDER = ('rules_missing', 'blocklists_missing', 'blocklists_stale', 'indicator_store_empty',
                'url_model_unavailable')
CONNECTION_SOURCES = ('firewall', 'sysmon3', 'snapshot')


class NetworkWindowsEngineError(RuntimeError):
    """Raised with a fixed reason code; never carries names, addresses or paths."""


# ---------------------------------------------------------------- shipped-item manifest

@dataclass(frozen=True)
class Shipped:
    sha256: str
    rules: dict[str, str]              # rule id -> samples | unvalidated_on_samples
    lists: dict[str, str]              # list name -> lock sha256


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(root: Path, relative: str, prefix: str) -> Path:
    path = (root / relative).resolve()
    base = (root / prefix).resolve()
    if base not in path.parents:
        raise NetworkWindowsEngineError('shipped_manifest_invalid')
    return path


def verify_manifest(path: Path = SHIPPED, root: Path = ROOT) -> Shipped:
    """Verify the shipped-item manifest; raise a reason code when it is absent or does not verify.

    Shape: {"schema": "network-windows-shipped-v1",
            "selection_rule": {"path": "evaluation/reports/<...>/selection_rule.md", "sha256": "<hex>"},
            "freeze": {"path": "evaluation/reports/<...>/FREEZE.json"},
            "rules": [{"id": "N1", "constants": {...}, "validation": "samples"|"unvalidated_on_samples"}],
            "lists": [{"name": "feodo_tracker", "lock_sha256": "<hex>", "licence": "..."}]}
    FREEZE.json must record the same `selection_rule_sha256`.
    """
    path = Path(path)
    if not path.is_file():
        raise NetworkWindowsEngineError('shipped_manifest_missing')
    raw = path.read_bytes()
    try:
        manifest = json.loads(raw.decode('utf-8'))
        if manifest['schema'] != MANIFEST_SCHEMA:
            raise NetworkWindowsEngineError('shipped_manifest_invalid')
        rule_path = _inside(root, manifest['selection_rule']['path'], 'evaluation/reports')
        rule_sha = str(manifest['selection_rule']['sha256']).lower()
        freeze_path = _inside(root, manifest['freeze']['path'], 'evaluation/reports')
        rules, lists = {}, {}
        for entry in manifest['rules']:
            rule = entry['id']
            if rule not in detections.SHIPPABLE or rule in rules or entry['validation'] not in VALIDATIONS:
                raise NetworkWindowsEngineError('shipped_manifest_invalid')
            if entry['constants'] != json.loads(json.dumps(detections.RULE_CONSTANTS[rule])):
                raise NetworkWindowsEngineError('shipped_rule_constants_mismatch')
            rules[rule] = entry['validation']
        for entry in manifest.get('lists', []):
            if entry['name'] not in blocklists_module.ALLOWED or entry['name'] in lists:
                raise NetworkWindowsEngineError('shipped_manifest_invalid')
            lists[entry['name']] = str(entry['lock_sha256']).lower()
    except NetworkWindowsEngineError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise NetworkWindowsEngineError('shipped_manifest_invalid') from None
    if not rules:
        raise NetworkWindowsEngineError('shipped_manifest_invalid')
    if not rule_path.is_file() or _sha256_file(rule_path) != rule_sha:
        raise NetworkWindowsEngineError('selection_rule_mismatch')
    try:
        freeze = json.loads(freeze_path.read_text(encoding='utf-8'))
        frozen = str(freeze['selection_rule_sha256']).lower()
    except (OSError, ValueError, KeyError, TypeError):
        raise NetworkWindowsEngineError('freeze_missing') from None
    if frozen != rule_sha:
        raise NetworkWindowsEngineError('freeze_mismatch')
    return Shipped(sha256=hashlib.sha256(raw).hexdigest(), rules=rules, lists=lists)


# ---------------------------------------------------------------- URL model (N4), read-only

@dataclass(frozen=True)
class UrlScorer:
    candidate_id: str
    threshold: float
    score: Callable[[str], float] = field(repr=False)


def load_url_scorer() -> UrlScorer | None:
    """The deployed URL model, only if it is the frozen candidate with the frozen threshold."""
    try:
        from app.engines import url_model
        from app.engines.phishing_findings import url_candidate_id
        artifact = url_model._load()
        if url_candidate_id() != detections.N4_URL_CANDIDATE or artifact is None:
            return None
        if float(artifact['thresholds']['medium']) != detections.N4_THRESHOLD:
            return None   # the frozen threshold is never changed (§2.1 N4)

        def score(url: str) -> float:
            result = url_model.score_url(url)
            if result is None:
                raise NetworkWindowsEngineError('url_model_unavailable')
            return float(result['probability'])
        return UrlScorer(detections.N4_URL_CANDIDATE, detections.N4_THRESHOLD, score)
    except Exception:   # a missing or unreadable model is a health reason, never a crash
        log.warning('network_windows_url_model_unavailable')
        return None


# ---------------------------------------------------------------- tables

def _related(alert, others) -> list:
    """Alerts for the same device, fixed hour and destination (same key, or an IP of the other)."""
    out = []
    for other in others:
        if other is alert or other.device_ref != alert.device_ref or other.hour != alert.hour:
            continue
        if other.dest == alert.dest or other.dest in alert.ips or alert.dest in other.ips:
            out.append(other)
    return out


def severity(alert, related) -> str:
    """§6.2. Combinations only raise severity; they never create another kind."""
    near = {r.detection for r in related}
    rule = alert.detection
    if rule == 'N1':
        return 'high' if 'blocklist_ip_connection' in alert.reasons else 'medium'
    if rule == 'N3':
        return 'medium'
    if rule == 'N4':
        return 'medium' if any(FAMILIES[r] != 'model' for r in near) else 'low'
    if rule == 'N5':
        return 'medium' if 'dga_nxdomain_burst' in alert.reasons else 'low'
    if rule == 'N6':
        if near & {'N1', 'N2'}:
            return 'high'
        return 'medium' if near & {'N5', 'N9'} else 'low'
    if rule == 'N7':
        return 'medium' if 'N6' in near else 'low'
    if rule == 'N8':
        return 'medium' if len(alert.reasons) >= 2 else 'low'
    if rule == 'N9':
        return 'info'
    raise NetworkWindowsEngineError('unknown_detection')


def confidence(alert, related, validation: str, connection_visible: bool) -> str:
    """§6.3. `confirmed` is never used."""
    families = {FAMILIES[alert.detection]} | {FAMILIES[r.detection] for r in related}
    if alert.detection == 'N1' and alert.reasons == {'blocklist_ip_dns_answer'} and not connection_visible:
        return 'undetermined'
    if alert.detection == 'N4' and families == {'model'}:
        return 'undetermined'
    if len(families) >= 2 and validation != 'unvalidated_on_samples':
        return 'corroborated'
    return 'single_signal'


def attack_refs(alert, related) -> list[dict]:
    """§5: T1568.002, T1071.004 and T1571 only. Nothing from a list hit, beaconing, a single
    DGA-like name, a single tunnelling sign, N3/N4 lookups or N9."""
    near = {r.detection for r in related}
    refs = []
    if alert.detection == 'N5' and 'dga_nxdomain_burst' in alert.reasons:
        refs.append(('T1568.002', 'n5_dga_nxdomain_burst'))
    if alert.detection == 'N8' and len(alert.reasons) >= 2:
        refs.append(('T1071.004', 'n8_two_or_more_signs'))
    if alert.detection == 'N7' and near & {'N1', 'N6'}:
        refs.append(('T1571', 'n7_with_' + '_'.join(sorted(near & {'N1', 'N6'})).lower()))
    return [{'technique_id': t, 'matrix': ATTACK_MATRIX, 'attack_version': ATTACK_VERSION, 'basis': b}
            for t, b in refs]


def indicators(alert, process_hashes: Mapping[str, str]) -> list[dict]:
    """§6.4: hash-only; local addresses never; N8 gives only the registered domain."""
    out = []
    if alert.dest_type == 'ip':
        if locality(alert.dest) == 'outside':
            normalized = normalize_ip(alert.dest)
            out.append({'type': 'ip', 'value_hash': normalized.value_hash, 'value': None, 'role': 'remote_endpoint'})
    else:
        digest = sha256_hex(alert.dest)
        out.append({'type': 'domain', 'value_hash': digest, 'value': None, 'role': 'resolved_name',
                    'registered_domain_hash': digest})
    for guid in sorted(alert.process_guids):
        digest = process_hashes.get(guid)
        if digest:
            normalized = normalize_hash(digest, 'sha256')
            ref = {'type': 'hash', 'value_hash': normalized.value_hash, 'value': None,
                   'role': 'connecting_process', 'hash_algo': 'sha256'}
            if ref not in out:
                out.append(ref)
    return out[:MAX_INDICATORS]


# ---------------------------------------------------------------- engine

@dataclass
class ImportOutcome:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    not_run: dict = field(default_factory=dict)
    alerts: int = 0


class NetworkWindowsEngine:
    name = ENGINE_NAME
    domain = DOMAIN

    def __init__(self, shipped: Shipped | None, manifest_error: str | None = None, *,
                 lists: blocklists_module.Blocklists | None = None, url_scorer: UrlScorer | None = None,
                 popular_rank: Callable[[str], int | None] | None = None):
        if shipped is None and manifest_error is None:
            manifest_error = 'shipped_manifest_missing'
        self.shipped, self.manifest_error = shipped, manifest_error
        self.lists = lists if lists is not None else blocklists_module.Blocklists()
        self.url_scorer, self.popular_rank = url_scorer, popular_rank

    def __repr__(self) -> str:
        return f'NetworkWindowsEngine(version={self.version!r})'

    @property
    def shipped_lists(self) -> tuple[str, ...]:
        """Lists named by the manifest whose loaded lock is the shipped lock."""
        if not self.shipped or not self.lists.lock_sha256:
            return ()
        return tuple(sorted(name for name, lock in self.shipped.lists.items()
                            if name in self.lists.lists and lock == self.lists.lock_sha256))

    @property
    def version(self) -> str:
        rules = self.shipped.sha256[:12] if self.shipped else 'none'
        lists = self.lists.lock_sha256[:12] if self.shipped_lists else 'none'
        url = self.url_scorer.candidate_id if self.url_scorer else 'none'
        return f'netwin-v1+rules:{rules}+lists:{lists}+url:{url}'

    @property
    def registrable(self) -> bool:
        return self.shipped is not None

    def health(self, context: Mapping[str, Any] | None = None) -> dict:
        context = context or {}
        problems = set()
        if not self.registrable:
            problems.add('rules_missing')
        if self.shipped and 'N1' in self.shipped.rules:
            list_health = self.lists.health(context.get('now'))
            if not self.shipped_lists:
                problems.add('blocklists_missing')
            elif list_health:
                problems.update(list_health)
        if self.shipped and 'N3' in self.shipped.rules and context.get('indicator_store_count') == 0:
            problems.add('indicator_store_empty')
        if self.shipped and 'N4' in self.shipped.rules and self.url_scorer is None:
            problems.add('url_model_unavailable')
        reasons = [r for r in HEALTH_ORDER if r in problems]
        return {'available': self.registrable, 'status': reasons[0] if reasons else 'available',
                'reason': reasons[0] if reasons else None, 'reasons': reasons,
                'rules_detail': None if self.registrable else self.manifest_error,
                'shipped_rules': sorted(self.shipped.rules) if self.shipped else [],
                'shipped_lists': list(self.shipped_lists)}

    def analyze(self, observation) -> list[Finding]:
        return self.process(observation).findings

    def process(self, observation) -> ImportOutcome:
        if not self.registrable:
            raise NetworkWindowsEngineError('engine_unavailable')
        if observation.kind != OBSERVATION_KIND or not str(observation.source_ref).startswith(SOURCE_PREFIX):
            raise NetworkWindowsEngineError('unsupported_observation')
        data = observation.data
        result: ReadResult = data['read']
        if any(r.computer is not None for r in [*result.dns, *result.connections]):
            raise NetworkWindowsEngineError('records_not_pseudonymised')
        rules = self.shipped.rules
        shipped_lists = set(self.shipped_lists)
        ip_lists = None
        if 'N1' in rules and shipped_lists:
            ip_lists = lambda ip: tuple(n for n in self.lists.lookup(ip) if n in shipped_lists)  # noqa: E731
        hashes = data.get('indicator_domain_hashes') if 'N3' in rules else None
        scorer = self.url_scorer if 'N4' in rules else None
        found = detections.run(
            result, ip_lists=ip_lists, indicator_domain_hashes=hashes,
            url_score=scorer.score if scorer else None, url_threshold=scorer.threshold if scorer else None,
            popular_rank=self.popular_rank, local_nets=tuple(data.get('local_nets') or ()))
        alerts = [a for a in found.alerts if a.detection in rules]
        coverage = coverage_report(result)
        connection_visible = any(coverage['sources'][s]['records'] for s in CONNECTION_SOURCES)
        created = datetime.now(timezone.utc)
        input_files = [f.sha256 for f in result.files]
        not_run = {k: v for k, v in found.not_run.items() if k in rules or k == 'N2'}
        not_run.update({k: 'not_shipped' for k in detections.SHIPPABLE if k not in rules})
        findings = []
        for alert in alerts:
            related = _related(alert, alerts)
            attack = attack_refs(alert, related)
            details = {
                'detection': alert.detection,
                'reason_codes': sorted(alert.reasons),
                'events': alert.events,
                'window': {'first': alert.first, 'last': alert.last},
                'values': dict(alert.details),
                'combined_with': sorted({r.detection for r in related}),
                'device_ref': alert.device_ref,
                'rule_validation': rules[alert.detection],
                'coverage': coverage['detections'],
                'baseline': found.baseline,
                'input_files_sha256': input_files,
                'process_category': 'unknown',
                'attack_basis': [ref['basis'] for ref in attack],
            }
            if alert.detection == 'N1':
                details['lists'] = [self.lists.attribution(n) for n in alert.details.get('lists', ())
                                    if n in shipped_lists]
            refs = indicators(alert, result.process_hashes)
            if any(r['type'] == 'hash' for r in refs):
                details['process_category'] = 'known_process_hash'
            findings.append(Finding.model_validate(dict(
                engine={'name': self.name, 'version': self.version}, domain=self.domain,
                kind=KINDS[alert.detection], severity=severity(alert, related),
                confidence=confidence(alert, related, rules[alert.detection], connection_visible),
                indicators=refs, attack=attack,
                evidence={'reasons': sorted(alert.reasons), 'details': details},
                observed_at=datetime.fromisoformat(alert.first.replace('Z', '+00:00')), created_at=created,
                source={'kind': 'import', 'ref': observation.source_ref})))
        return ImportOutcome(findings=findings, coverage=coverage, not_run=not_run, alerts=len(alerts))

    def close(self) -> None:
        return None


# ---------------------------------------------------------------- loading and registration

def load_popular(path: Path | None = None) -> Callable[[str], int | None] | None:
    """Ranks from the local Tranco snapshot (`rank,domain` CSV); None when it is absent."""
    import csv
    path = Path(path) if path else ROOT / 'data' / 'raw' / 'tranco_final_approved.csv'
    if not path.is_file():
        return None
    ranks: dict[str, int] = {}
    with path.open(encoding='utf-8', newline='') as handle:
        for row in csv.DictReader(handle):
            try:
                rank, domain = int(row['rank']), row['domain'].strip().lower().rstrip('.')
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
            if domain and (domain not in ranks or rank < ranks[domain]):
                ranks[domain] = rank
    return ranks.get


def load_engine(manifest: Path = SHIPPED, root: Path = ROOT, lock: Path = blocklists_module.LOCK,
                url_scorer: UrlScorer | None | bool = True, popular: Path | None = None) -> NetworkWindowsEngine:
    """Build the engine from local files. A missing or failing part is a health reason."""
    try:
        shipped, error = verify_manifest(manifest, root), None
    except NetworkWindowsEngineError as exc:
        shipped, error = None, str(exc)
    try:
        lists = blocklists_module.load(lock, root)
    except blocklists_module.BlocklistError:
        lists = blocklists_module.Blocklists()
    scorer = load_url_scorer() if url_scorer is True else (url_scorer or None)
    return NetworkWindowsEngine(shipped, error, lists=lists, url_scorer=scorer, popular_rank=load_popular(popular))


def register(target=None, engine: NetworkWindowsEngine | None = None) -> NetworkWindowsEngine | None:
    """Register `network.windows` only when its shipped-item manifest verifies. Not called at import."""
    if target is None:
        from app.engines.registry import registry as target
    engine = engine if engine is not None else load_engine()
    if not engine.registrable:
        log.info('network.windows not registered: %s', engine.health().get('rules_detail'))
        return None
    return target.register(engine)
