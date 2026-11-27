"""Write ETIS incidents and shareable indicators as one STIX 2.1 bundle to a local file (design core-v2 §1).

    python data/scripts/export_stix.py [--incident ID ... | --since YYYY-MM-DD | --open]
                                       [--include-resolved-benign] [--tlp amber|green|white]
                                       [--out PATH]

Offline only: the command reads the local database (and, for abuse.ch list matches, the locally
pinned list files), writes one file, and makes no network call. When run as a script, socket
connections are blocked in this process. Nothing is uploaded or shared; sharing the file is the
owner's own decision.

Licence filter (§1.4): only values from redistributable sources are exported, namely
analyst-entered values, confirmed community values whose reporter accepted CC0, and IPs in
the CC0 abuse.ch Feodo Tracker list (SSL Blacklist is deprecated and not used). OpenPhish and PhishTank values,
scan-derived hash-only values and malware file hashes are counted, never written. Patterns
hold real values (§1.5); only the bundle note's human-readable list is de-fanged. The
terminal output holds counts only, never a value.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))

from app.core.defang import defang  # noqa: E402
from app.core.url_utils import parse_url, url_hash  # noqa: E402
from app.services import stix_export as sx  # noqa: E402

EXIT_OK, EXIT_REFUSED = 0, 2
NAMESPACE_ENV = 'ETIS_STIX_NAMESPACE'
DEFAULT_DIR = ROOT / 'var' / 'exports'
TLP_HELP = ('TLP marking for every object (default: amber). '
            'white = TLP:WHITE (STIX 2.1 built-in TLP 1.0 marking; TLP 2.0 calls it CLEAR)')
RESTRICTED_FEEDS = ('openphish', 'phishtank')
RESOLVED_EXCLUDED = ('false_positive', 'benign')
CC0_LISTS = ('feodo_tracker',)
# §1.4: the only sources whose values may be written, each with its docs/data-licences.md entry.
EXPORTABLE_SOURCES = {
    'analyst': 'ETIS analyst-entered values (feed:manual, analyst:*), subject to the restricted-feed check (Q14)',
    'community': 'Confirmed community reports whose reporter accepted CC0 (Q15), subject to the restricted-feed check (Q18)',
    'list:feodo_tracker': 'abuse.ch Feodo Tracker IP blocklist, CC0 (docs/data-licences.md abuse_ch_network_blocklists)',
}
COMMUNITY_LICENCE = 'CC0-1.0'
N1_REASONS = frozenset({'blocklist_ip_connection', 'blocklist_ip_dropped', 'blocklist_ip_dns_answer'})
# One reason per value that is counted instead of written, most specific first.
REASON_ORDER = ('restricted_feed_overlap', 'community_licence_not_accepted', 'list_not_installed',
                'restricted_feed', 'phone_no_pattern', 'hash_only', 'source_not_redistributable')


class ExportRefused(Exception):
    """Raised with a fixed reason code; never carries values or paths."""


def block_network() -> None:
    """Process-wide: no socket may connect while the command runs."""
    import socket

    def blocked(*args, **kwargs):
        raise OSError('network_blocked_in_export_stix')
    for name in ('connect', 'connect_ex', 'sendto'):
        setattr(socket.socket, name, blocked)
    socket.create_connection = blocked
    socket.getaddrinfo = blocked


def load_namespace(env_file=None) -> uuid.UUID:
    value = os.getenv(NAMESPACE_ENV, '').strip()
    if not value:
        path = Path(env_file) if env_file is not None else ROOT / '.env'
        if path.is_file():
            from dotenv import dotenv_values
            value = (dotenv_values(path).get(NAMESPACE_ENV) or '').strip()
    if not value:
        raise ExportRefused('stix_namespace_missing')
    try:
        return sx.namespace_from(value)
    except sx.StixExportError:
        raise ExportRefused('stix_namespace_invalid') from None


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--incident', type=int, action='append', metavar='ID', help='export these incidents')
    scope.add_argument('--since', type=date.fromisoformat, metavar='YYYY-MM-DD',
                       help='incidents with activity on or after this date')
    scope.add_argument('--open', action='store_true', help='open and investigating incidents (the default)')
    parser.add_argument('--include-resolved-benign', action='store_true',
                        help='also export incidents resolved false_positive or benign')
    parser.add_argument('--tlp', choices=('amber', 'green', 'white'), default='amber', help=TLP_HELP)
    parser.add_argument('--out', help='output file (default: var/exports/etis-stix-<UTC>.json); never overwritten')
    return parser.parse_args(argv)


# ---------------------------------------------------------------- scope

def select_incidents(db, args) -> list:
    from app.models import Incident
    query = db.query(Incident)
    if args.incident:
        query = query.filter(Incident.id.in_(sorted(set(args.incident))))
    elif args.since is not None:
        query = query.filter(Incident.last_activity_at >= datetime.combine(args.since, datetime.min.time()))
    else:
        query = query.filter(Incident.status.in_(('open', 'investigating')))
    incidents = query.order_by(Incident.id).all()
    if not args.include_resolved_benign:
        incidents = [i for i in incidents if not (i.status == 'resolved' and i.resolution in RESOLVED_EXCLUDED)]
    return incidents


# ---------------------------------------------------------------- licence filter (§1.4)

def _host(url: str) -> str | None:
    try:
        return parse_url(url).host
    except Exception:
        return None


def restricted_records(db) -> dict:
    """Every stored OpenPhish/PhishTank record, active or not (Q14 rule 2). Read only."""
    from app.models import BlacklistEntry, FeedObservation, FeedSnapshot, IndicatorSighting
    url_hashes, domains = set(), set()
    for row in db.query(FeedObservation.url_hash).filter(FeedObservation.source.in_(RESTRICTED_FEEDS)):
        url_hashes.add(row.url_hash)
    for row in db.query(BlacklistEntry.url_hash, BlacklistEntry.domain).filter(
            BlacklistEntry.source.in_(RESTRICTED_FEEDS)):
        url_hashes.add(row.url_hash)
        domains.add(row.domain.lower().rstrip('.'))
    for snapshot in db.query(FeedSnapshot).filter(FeedSnapshot.source.in_(RESTRICTED_FEEDS)):
        for url in snapshot.payload or ():
            try:
                url_hashes.add(url_hash(url))
            except Exception:
                continue
            host = _host(url)
            if host:
                domains.add(host)
    indicator_ids = {row.indicator_id for row in db.query(IndicatorSighting.indicator_id).filter(
        IndicatorSighting.source_kind == 'feed', IndicatorSighting.source_name.in_(RESTRICTED_FEEDS))}
    return {'url_hashes': url_hashes, 'domains': domains, 'indicator_ids': indicator_ids}


def overlaps_restricted(indicator, restricted) -> bool:
    if indicator.id in restricted['indicator_ids']:
        return True
    if indicator.type == 'url' and indicator.value_hash in restricted['url_hashes']:
        return True
    return indicator.type == 'domain' and (indicator.value or '') in restricted['domains']


def list_values(lists) -> dict[str, tuple[str, tuple[str, ...]]]:
    """value_hash -> (canonical IP, CC0 list names) for every IP in a verified local list."""
    from app.core.indicators import normalize_ip
    out = {}
    for ip, names in (lists.ips.items() if lists is not None else ()):
        try:
            normalized = normalize_ip(ip)
        except ValueError:
            continue
        names = tuple(n for n in names if n in CC0_LISTS)
        if names:
            out[normalized.value_hash] = (normalized.value, names)
    return out


def community_accepted(db, sighting) -> bool:
    """Q15: exported only when the report records CC0 acceptance. No submission form records it yet."""
    from app.models import CommunityReport
    ref = sighting.ref or ''
    if not ref.startswith('community_reports:'):
        return False
    try:
        report = db.get(CommunityReport, int(ref.split(':', 1)[1]))
    except ValueError:
        return False
    return report is not None and getattr(report, 'licence_accepted', None) == COMMUNITY_LICENCE


def classify(db, indicator, sightings, *, restricted, cc0, lists_installed, n1_candidate) -> tuple[str | None, list[str], str]:
    """(value to export or None, allowed source labels, reason when not exported)."""
    reasons, allowed = set(), []
    for s in sightings:
        if s.source_kind == 'feed' and s.source_name in RESTRICTED_FEEDS:
            reasons.add('restricted_feed')
        elif (s.source_kind == 'feed' and s.source_name == 'manual') or s.source_kind == 'analyst':
            declared = s.source_name if s.source_kind == 'analyst' else 'manual'
            if declared in RESTRICTED_FEEDS or overlaps_restricted(indicator, restricted):
                reasons.add('restricted_feed_overlap')
            elif indicator.value is not None:
                allowed.append(f'analyst:{declared}')
        elif s.source_kind == 'community':
            if not community_accepted(db, s):
                reasons.add('community_licence_not_accepted')
            elif overlaps_restricted(indicator, restricted):
                reasons.add('restricted_feed_overlap')
            elif indicator.value is not None:
                allowed.append('community:community_reports')
        else:
            reasons.add('source_not_redistributable')
    value = indicator.value if allowed else None
    if indicator.type == 'ip' and indicator.value_hash in cc0:
        listed_value, names = cc0[indicator.value_hash]
        allowed += [f'list:{n}' for n in names]
        value = listed_value
    elif indicator.type == 'ip' and n1_candidate and not lists_installed:
        reasons.add('list_not_installed')
    if allowed and indicator.type == 'phone':
        allowed, value = [], None
        reasons.add('phone_no_pattern')
    if allowed:
        return value, sorted(set(allowed)), ''
    if indicator.value is None:
        reasons.add('hash_only')
    reason = next((r for r in REASON_ORDER if r in reasons), 'source_not_redistributable')
    return None, [], reason


# ---------------------------------------------------------------- bundle

def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def build_bundle(db, incidents, *, namespace, tlp: str, lists, now: datetime) -> tuple[dict, dict]:
    from app.models import AttackTechnique, FindingAttack, FindingIndicator, FindingRecord, Indicator, IndicatorSighting
    ident = sx.identity(namespace, tlp=tlp)
    objects = {ident['id']: ident}
    marking = sx.tlp_marking(tlp)
    objects[marking['id']] = marking
    restricted = restricted_records(db)
    cc0 = list_values(lists)
    lists_installed = bool(lists is not None and lists.lists)
    counted = Counter()
    counted_by_type = Counter()
    exported_values: dict[str, tuple[str, str]] = {}
    sources_used: set[str] = set()
    decisions: dict[int, tuple] = {}
    attack_objects: dict[tuple, dict] = {}
    incident_refs = []

    for inc in incidents:
        findings = db.query(FindingRecord).filter(FindingRecord.incident_id == inc.id).order_by(
            FindingRecord.observed_at, FindingRecord.id).all()
        finding_counts = {'kind': Counter(), 'engine': Counter(), 'severity': Counter()}
        links = defaultdict(list)
        for f in findings:
            finding_counts['kind'][f.kind] += 1
            finding_counts['engine'][f.engine_name] += 1
            finding_counts['severity'][f.severity] += 1
        uncatalogued, basis_by_attack, attack_by_finding = set(), defaultdict(set), defaultdict(set)
        for f in findings:
            for fa in db.query(FindingAttack).filter(FindingAttack.finding_id == f.id).order_by(
                    FindingAttack.technique_id, FindingAttack.matrix):
                key = (fa.technique_id, fa.matrix, fa.attack_version)
                tech = db.get(AttackTechnique, {'technique_id': fa.technique_id, 'matrix': fa.matrix,
                                                'attack_version': fa.attack_version})
                if tech is None:
                    uncatalogued.add(f'{fa.matrix}:{fa.technique_id}')
                    continue
                if key not in attack_objects:
                    attack_objects[key] = sx.attack_pattern(
                        namespace, technique_id=tech.technique_id, matrix=tech.matrix,
                        attack_version=tech.attack_version, name=tech.name, url=tech.url,
                        mitre_stix_id=tech.stix_id, identity_ref=ident['id'], tlp=tlp, created=f.observed_at)
                basis_by_attack[key].add(fa.basis)
                attack_by_finding[f.id].add(key)
        custom = {'x_etis_status': inc.status, 'x_etis_severity': inc.severity, 'x_etis_resolution': inc.resolution,
                  'x_etis_domain': inc.domain,
                  'x_etis_finding_counts': {k: dict(sorted(v.items())) for k, v in finding_counts.items() if v},
                  'x_etis_attack_ids': sorted(uncatalogued)}
        inc_obj = sx.incident(namespace, incident_id=inc.id, title=inc.title, opened_at=inc.opened_at,
                              last_activity_at=inc.last_activity_at, identity_ref=ident['id'], tlp=tlp, custom=custom)
        objects[inc_obj['id']] = inc_obj
        incident_refs.append(inc_obj['id'])

        for f in findings:
            for fi in db.query(FindingIndicator).filter(FindingIndicator.finding_id == f.id).order_by(
                    FindingIndicator.indicator_id, FindingIndicator.role):
                indicator = db.get(Indicator, fi.indicator_id)
                if indicator is None:
                    continue
                if indicator.id not in decisions:
                    sightings = db.query(IndicatorSighting).filter(
                        IndicatorSighting.indicator_id == indicator.id).order_by(IndicatorSighting.id).all()
                    n1 = f.engine_name == 'network.windows' and bool(N1_REASONS & set(f.evidence.get('reasons', [])))
                    value, allowed, reason = classify(db, indicator, sightings, restricted=restricted, cc0=cc0,
                                                      lists_installed=lists_installed, n1_candidate=n1)
                    ind_obj = None
                    if value is not None:
                        ind_obj = sx.indicator(namespace, indicator_id=indicator.id, kind=indicator.type,
                                               value=value, first_seen=indicator.first_seen,
                                               identity_ref=ident['id'], tlp=tlp, sources=allowed,
                                               hash_algo=indicator.hash_algo)
                    if ind_obj is None:
                        counted[reason or 'phone_no_pattern'] += 1
                        counted_by_type[indicator.type] += 1
                    else:
                        objects[ind_obj['id']] = ind_obj
                        exported_values[ind_obj['id']] = (indicator.type, value)
                        sources_used.update(allowed)
                    decisions[indicator.id] = ind_obj
                ind_obj = decisions[indicator.id]
                if ind_obj is None:
                    continue
                links[ind_obj['id']].append(f)
                engine = {'name': f.engine_name, 'version': f.engine_version}
                sight = sx.sighting(namespace, finding_id=f.id, indicator_ref=ind_obj['id'],
                                    observed_at=f.observed_at, identity_ref=ident['id'], tlp=tlp,
                                    custom={'x_etis_engine': engine, 'x_etis_kind': f.kind,
                                            'x_etis_severity': f.severity, 'x_etis_confidence': f.confidence,
                                            'x_etis_reasons': list(f.evidence.get('reasons', []))})
                objects[sight['id']] = sight

        for ind_ref, linked in sorted(links.items()):
            first = min(f.observed_at for f in linked)
            rel = sx.relationship(namespace, relationship_type='related-to', source_ref=inc_obj['id'],
                                  target_ref=ind_ref, identity_ref=ident['id'], tlp=tlp, created=first)
            objects[rel['id']] = rel
            for key in sorted({k for f in linked for k in attack_by_finding[f.id]}):
                ap = attack_objects[key]
                objects[ap['id']] = ap
                rel = sx.relationship(namespace, relationship_type='indicates', source_ref=ind_ref,
                                      target_ref=ap['id'], identity_ref=ident['id'], tlp=tlp, created=first)
                objects[rel['id']] = rel
        for key in sorted(basis_by_attack):
            ap = attack_objects[key]
            objects[ap['id']] = ap
            rel = sx.relationship(namespace, relationship_type='related-to', source_ref=inc_obj['id'],
                                  target_ref=ap['id'], identity_ref=ident['id'], tlp=tlp, created=inc.opened_at,
                                  custom={'x_etis_basis': sorted(basis_by_attack[key])})
            objects[rel['id']] = rel

    attack_present = any(o['type'] == 'attack-pattern' for o in objects.values())
    content = note_content(exported_values, counted, sources_used, attack_present)
    nt = sx.note(namespace, key='export-summary', content=content, object_refs=incident_refs,
                 identity_ref=ident['id'], tlp=tlp, created=now, abstract='ETIS export summary')
    objects[nt['id']] = nt
    data = sx.bundle(list(objects.values()))
    summary = {'objects': dict(sorted(Counter(o['type'] for o in data['objects']).items())),
               'indicators_exported': len(exported_values),
               'not_exported_by_reason': dict(sorted(counted.items())),
               'not_exported_by_type': dict(sorted(counted_by_type.items()))}
    return data, summary


def note_content(exported_values, counted, sources_used, attack_present) -> str:
    lines = ['ETIS STIX 2.1 export.',
             'Indicator patterns hold the real values for machine matching.',
             'Values below are de-fanged for safe reading; the indicator patterns hold the real values.']
    for kind, value in sorted(exported_values.values()):
        lines.append(f'- {kind}: {defang(kind, value)}')
    lines.append('Sources of exported values and their licences:')
    groups = sorted({s if s.startswith('list:') else s.split(':', 1)[0] for s in sources_used})
    for group in groups:
        lines.append(f'- {group}: {EXPORTABLE_SOURCES[group]}')
    if not groups:
        lines.append('- none')
    lines.append('Values counted but not exported, by reason: '
                 + (', '.join(f'{k}={v}' for k, v in sorted(counted.items())) or 'none') + '.')
    if attack_present:
        lines.append(sx.ATTACK_NOTICE)
    return '\n'.join(lines)


# ---------------------------------------------------------------- output

def output_path(args, now: datetime) -> Path:
    if args.out:
        return Path(args.out)
    return DEFAULT_DIR / f"etis-stix-{now.strftime('%Y%m%dT%H%M%SZ')}.json"


def write_new_file(path: Path, data: dict) -> None:
    """Write to a temporary name, then rename; never overwrite an existing file."""
    if path.exists():
        raise ExportRefused('output_exists')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{uuid.uuid4().hex}.tmp')
    try:
        with open(temporary, 'x', encoding='utf-8', newline='\n') as handle:
            json.dump(data, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write('\n')
        if path.exists():
            raise ExportRefused('output_exists')
        os.rename(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_lists():
    from app.engines.network_windows import blocklists
    try:
        return blocklists.load()
    except blocklists.BlocklistError:
        return None


def main(argv=None, *, session_factory=None, env_file=None, out=None, lists_loader=None, now=None) -> int:
    args = parse_args(argv)
    out = out or sys.stdout
    now = now or datetime.now(timezone.utc)
    try:
        namespace = load_namespace(env_file)
        if session_factory is None:
            from app.core.database import SessionLocal as session_factory
        with session_factory() as db:
            incidents = select_incidents(db, args)
            if not incidents:
                raise ExportRefused('no_incidents_in_scope')
            lists = (lists_loader or load_lists)()
            data, summary = build_bundle(db, incidents, namespace=namespace, tlp=args.tlp, lists=lists,
                                         now=_naive(now))
            db.rollback()   # read only: nothing to keep
        problems = sx.validate_bundle(data)
        if problems:
            raise ExportRefused('bundle_invalid')
        path = output_path(args, now)
        write_new_file(path, data)
    except ExportRefused as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return EXIT_REFUSED
    report = {'written': str(path), 'tlp': args.tlp, 'incidents': len(incidents), **summary}
    print(json.dumps(report, indent=2), file=out)
    return EXIT_OK


if __name__ == '__main__':
    block_network()
    sys.exit(main())
