"""Build the network.windows expected-detection manifest (design network-windows-v1 §3.2, §4.6 gate 2, §9 step 6).

Method: the host engine's method, unchanged (host-engine-v1 §3.2, §4.5 gate 2, §4.7 item 3).
Expected detections per sample come only from the sample's path-derived ATT&CK techniques and
the design's rule text, and are written **before any detection is run on any sample**:

- Per-file techniques are taken from the host engine's frozen, path-only technique manifest
  (`evaluation/reports/2026-11-host-v1/technique_manifest.json`, built from folder and file
  names by `evaluation/host_technique_manifest.py`; no sample was opened). Its SHA-256 must
  equal the value frozen in the host `FREEZE.json`. No new keyword table is written, so no
  label was chosen with the network rules in view.
- Gate techniques per rule are the techniques design §5 maps to that rule, and only those:
  N5 `T1568.002` (burst), N7 `T1571`, N8 `T1071.004`. N1-N4, N6 and N9 map to no technique
  in §5, so no sample can oblige them. Matching is exact, as host §4.7 item 3: a parent
  technique never matches a sub-technique or the reverse.
- Rule-text exclusions (design §3.2, §4.3, §10 decision 1): N1 list hits are proven by unit
  tests only; N2 is inactive in v1; N9 emits nothing on samples (each sample is its own
  import with `baseline: none`).
- A rule with no expected development-half file must pass its invented positive and negative
  tests and then ships `unvalidated_on_samples` (gate 2).

Sources (design §11 S1-S3): S1 EVTX-ATTACK-SAMPLES (pinned, GPL-3.0) is used through the
path labels above; S2 UMUDGA is not used (its bundle contains DGA executables; owner decision
of 27 November 2026); S3 no DNS-tunnelling sample in Windows log form was found.

Usage:
    python evaluation/network_expected_detections.py                 # write the manifest
    python evaluation/network_expected_detections.py --verify-samples DIR
        # read-only: hash each pinned sample under DIR and compare size and SHA-256 with the
        # lock. Files are read as bytes only; no event is parsed and nothing is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'data/evtx-attack-samples-lock.json'
HOST_REPORT = ROOT / 'evaluation/reports/2026-11-host-v1'
HOST_MANIFEST = HOST_REPORT / 'technique_manifest.json'
HOST_FREEZE = HOST_REPORT / 'FREEZE.json'
OUTPUT = ROOT / 'evaluation/reports/2026-11-network-windows-v1/expected_detections.json'

RULES = ('N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9')
# Design §5 (ATT&CK v20.0), copied: the only rule-to-technique links. Written before any measurement.
GATE_TECHNIQUES = {
    'N5': ('T1568.002',),   # dga_nxdomain_burst; a single DGA-like name maps to nothing
    'N7': ('T1571',),       # only together with N1 or N6 for the same destination
    'N8': ('T1071.004',),   # two or more signs, or dns_txt_burst with another sign
}
# Design rule text that removes a rule from sample obligations whatever the labels say.
EXCLUDED = {
    'N1': 'list hits are proven by unit tests with invented lists only; no live malicious traffic (§3.2)',
    'N2': 'inactive in v1: no list provides hosts (§2.1, §10 decision 1)',
    'N9': 'each sample is its own import with baseline: none, so N9 emits nothing on samples (§4.3)',
}
NO_MAPPING = 'design §5 maps no ATT&CK technique to this rule, so no sample label can oblige it'
# Network-related techniques present in sample labels but listed as "not mapped" in design §5.
NOT_MAPPED_NETWORK = ('T1041', 'T1048', 'T1048.003', 'T1071', 'T1090', 'T1090.001', 'T1095', 'T1105',
                      'T1568', 'T1572', 'T1573')
SOURCES = {
    'S1': {'name': 'EVTX-ATTACK-SAMPLES', 'status': 'used',
           'basis': 'pinned commit 4ceed2f4706daf601c212a8f91c113dd85349a2c, GPL-3.0, files stay under ignored '
                    'data/external/; per-file techniques from the frozen host path-only manifest'},
    'S2': {'name': 'UMUDGA (Mendeley Data 10.17632/y8ph45msv8.1)', 'status': 'not_used',
           'basis': 'not used: contains executables (the bundle includes DGA executables); owner decision of '
                    '2026-11-27. Licence shown on the dataset page: MIT. Not downloaded.'},
    'S3': {'name': 'DNS-tunnelling sample in Windows log form', 'status': 'none_found',
           'basis': 'searched 2026-11-27: public DNS-tunnelling datasets found are PCAP/CSV, which v1 does not read'},
}


def lf_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def load_host_manifest(path: Path = HOST_MANIFEST, freeze: Path = HOST_FREEZE) -> dict:
    """The host path-only manifest, refused unless it equals the frozen bytes (LF-normalised)."""
    frozen = json.loads(freeze.read_text(encoding='utf-8'))['files']['technique_manifest.json']['sha256']
    if lf_sha256(path) != frozen:
        raise ValueError('host_technique_manifest_not_frozen_bytes')
    return json.loads(path.read_text(encoding='utf-8'))


def matches(rule: str, techniques) -> bool:
    """Exact technique equality only (host §4.7 item 3)."""
    return bool(set(GATE_TECHNIQUES.get(rule, ())) & set(techniques))


def build(host: dict, lock: dict) -> dict:
    if host['commit'] != lock['commit'] or host['source'] != lock['source']:
        raise ValueError('host_manifest_lock_mismatch')
    pinned = {entry['sha256'] for entry in lock['files'] if entry['path'].endswith('.evtx')}
    samples = host['samples']
    if {s['sha256'] for s in samples} != pinned:
        raise ValueError('host_manifest_lock_mismatch')
    rules = {}
    for rule in RULES:
        expected = [s for s in samples if s['status'] == 'labelled' and rule not in EXCLUDED and matches(rule, s['techniques'])]
        dev = sorted(s['sha256'] for s in expected if s['split'] == 'development')
        rep = sorted(s['sha256'] for s in expected if s['split'] == 'report')
        if rule in EXCLUDED:
            reason = EXCLUDED[rule]
        elif rule not in GATE_TECHNIQUES:
            reason = NO_MAPPING
        elif not dev:
            reason = 'no development-half sample carries a gate technique'
        else:
            reason = 'development-half samples carry a gate technique'
        rules[rule] = {
            'gate_techniques': list(GATE_TECHNIQUES.get(rule, ())),
            'expected_development': dev, 'expected_report': rep,
            'gate_2': 'must_alert_on_an_expected_development_file' if dev else
                      ('inactive' if rule == 'N2' else 'invented_tests_then_unvalidated_on_samples'),
            'reason': reason,
        }
    seen_not_mapped = []
    for s in samples:
        found = sorted(set(s['techniques']) & set(NOT_MAPPED_NETWORK))
        if found:
            seen_not_mapped.append({'sha256': s['sha256'], 'paths': s['paths'], 'split': s['split'],
                                    'techniques': found})
    return {
        'description': 'Expected detections of network.windows rules per EVTX-ATTACK-SAMPLES file, from path-derived '
                       'ATT&CK techniques (frozen host manifest) and the rule-to-technique map of design §5 only. '
                       'Written before any detection was run on any sample. Exposed development evidence.',
        'design': 'docs/design/network-windows-v1.md §3.2, §4.6 gate 2, §5',
        'method': 'host-engine-v1 §3.2 and §4.7 item 3 (exact technique match), unchanged',
        'source': lock['source'], 'commit': lock['commit'], 'attack_version': host['attack_version'],
        'split_rule': host['split_rule'],
        'inputs': {
            'evaluation/reports/2026-11-host-v1/technique_manifest.json': {'sha256_lf': lf_sha256(HOST_MANIFEST)},
            'data/evtx-attack-samples-lock.json': {'sha256_lf': lf_sha256(LOCK)},
        },
        'sources': SOURCES,
        'counts': {'samples': len(samples), 'labelled': sum(s['status'] == 'labelled' for s in samples),
                   'development': sum(s['split'] == 'development' for s in samples),
                   'report': sum(s['split'] == 'report' for s in samples),
                   'rules_with_expected_development_files': sum(bool(r['expected_development']) for r in rules.values()),
                   'samples_with_network_techniques_not_mapped': len(seen_not_mapped)},
        'rules': rules,
        'not_mapped_network_techniques_seen': {
            'note': 'Listed for transparency only; design §5 maps none of these to any rule, so they create no '
                    'obligation.',
            'samples': seen_not_mapped,
        },
        'limitations': [
            'No rule has an expected development-half sample: every shipped rule passes gate 2 only through its '
            'invented tests and ships unvalidated_on_samples, with confidence capped at single_signal.',
            'N5 (DGA) would be validated by a labelled DGA list; UMUDGA is not used because it contains executables.',
            'N8 (DNS tunnelling) has no public sample in Windows log form.',
            'Labels are coarse: a name says what the lab exercised, not that every event is malicious.',
        ],
    }


def verify_samples(directory: Path, lock: dict) -> dict:
    """Read-only size and SHA-256 check of the pinned files under `directory`. Bytes only; nothing parsed or written."""
    base = Path(directory) / lock['directory']
    counts = {'ok': 0, 'missing': 0, 'size_mismatch': 0, 'sha256_mismatch': 0}
    for entry in lock['files']:
        path = base / entry['path']
        try:
            size = path.stat().st_size
        except OSError:
            counts['missing'] += 1
            continue
        if size != entry['size']:
            counts['size_mismatch'] += 1
            continue
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        counts['ok' if digest.hexdigest() == entry['sha256'] else 'sha256_mismatch'] += 1
    return counts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--verify-samples', type=Path, help='folder holding the pinned samples (read-only check)')
    args = parser.parse_args(argv)
    lock = json.loads(LOCK.read_text(encoding='utf-8'))
    if args.verify_samples:
        counts = verify_samples(args.verify_samples, lock)
        print(json.dumps({'files': len(lock['files']), **counts}))
        return 0 if counts['ok'] == len(lock['files']) else 1
    manifest = build(load_host_manifest(), lock)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes((json.dumps(manifest, indent=1, ensure_ascii=False) + '\n').encode('utf-8'))
    print(json.dumps(manifest['counts']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
