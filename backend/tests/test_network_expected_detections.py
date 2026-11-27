"""network.windows expected-detection manifest (design network-windows-v1 §3.2, §4.6 gate 2, §5, §9 step 6).

The manifest is built from the frozen host path-only technique manifest and design §5; no
sample is opened. The optional sample check hashes bytes only. Invented samples here use
made-up hashes; no file is read outside tmp_path.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('network_expected', ROOT / 'evaluation/network_expected_detections.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
OUTPUT = ROOT / 'evaluation/reports/2026-11-network-windows-v1/expected_detections.json'
LOCK = json.loads((ROOT / 'data/evtx-attack-samples-lock.json').read_text(encoding='utf-8'))


def test_committed_manifest_is_reproducible_from_frozen_inputs():
    built = tool.build(tool.load_host_manifest(), LOCK)
    assert json.loads(OUTPUT.read_text(encoding='utf-8')) == built


def test_gate_techniques_are_exactly_the_design_section_5_map():
    assert tool.GATE_TECHNIQUES == {'N5': ('T1568.002',), 'N7': ('T1571',), 'N8': ('T1071.004',)}
    design = (ROOT / 'docs/design/network-windows-v1.md').read_text(encoding='utf-8')
    section = design.split('## 5. ATT&CK v20.0', 1)[1].split('## 6.', 1)[0]
    for rule, (technique,) in tool.GATE_TECHNIQUES.items():
        assert f'`{technique}`' in section and rule in section


@pytest.mark.parametrize('rule, techniques, expected', [
    ('N5', ['T1568.002'], True),
    ('N5', ['T1568'], False),             # a parent never matches a sub-technique
    ('N8', ['T1071'], False),
    ('N8', ['T1071.004', 'T1105'], True),
    ('N7', ['T1571'], True),
    ('N7', ['T1572', 'T1090.001'], False),  # tunnelling and proxying are "not mapped" in §5
    ('N6', ['T1571', 'T1568.002'], False),  # no §5 technique for N6
    ('N1', ['T1571'], False),
])
def test_matching_is_exact(rule, techniques, expected):
    assert tool.matches(rule, techniques) is expected


def invented(rows):
    lock = {'source': 'invented/source', 'commit': 'c' * 40, 'directory': 'd',
            'files': [{'path': f'x/{i}.evtx', 'size': 1, 'sha256': sha} for i, (sha, *_rest) in enumerate(rows)]}
    host = {'source': 'invented/source', 'commit': 'c' * 40, 'attack_version': '20.0', 'split_rule': 'r',
            'samples': [{'sha256': sha, 'paths': [f'x/{i}.evtx'], 'split': split, 'techniques': techniques,
                         'status': 'labelled' if techniques else 'excluded_undetermined'}
                        for i, (sha, split, techniques) in enumerate(rows)]}
    return host, lock


def test_rules_get_obligations_only_from_development_files_with_gate_techniques():
    host, lock = invented([('a' * 64, 'development', ['T1568.002']), ('b' * 64, 'report', ['T1071.004']),
                           ('c' * 64, 'development', ['T1572']), ('d' * 64, 'development', ['T1571'])])
    rules = tool.build(host, lock)['rules']
    assert rules['N5']['expected_development'] == ['a' * 64]
    assert rules['N5']['gate_2'] == 'must_alert_on_an_expected_development_file'
    assert rules['N8']['expected_report'] == ['b' * 64] and rules['N8']['expected_development'] == []
    assert rules['N8']['gate_2'] == 'invented_tests_then_unvalidated_on_samples'
    assert rules['N7']['expected_development'] == ['d' * 64]
    for rule in ('N1', 'N3', 'N4', 'N6', 'N9'):
        assert rules[rule]['expected_development'] == [] and rules[rule]['gate_2'] == \
            'invented_tests_then_unvalidated_on_samples'
    assert rules['N2']['gate_2'] == 'inactive'


def test_the_host_manifest_must_be_the_frozen_bytes_and_match_the_lock(tmp_path):
    changed = tmp_path / 'technique_manifest.json'
    changed.write_bytes(tool.HOST_MANIFEST.read_bytes() + b' ')
    with pytest.raises(ValueError, match='host_technique_manifest_not_frozen_bytes'):
        tool.load_host_manifest(changed)
    host, lock = invented([('a' * 64, 'development', ['T1571'])])
    lock['files'][0]['sha256'] = 'e' * 64
    with pytest.raises(ValueError, match='host_manifest_lock_mismatch'):
        tool.build(host, lock)


def test_current_result_every_rule_is_unvalidated_on_samples_and_sources_are_recorded():
    manifest = json.loads(OUTPUT.read_text(encoding='utf-8'))
    assert manifest['counts']['rules_with_expected_development_files'] == 0
    assert all(not r['expected_development'] and not r['expected_report'] for r in manifest['rules'].values())
    assert manifest['sources']['S2']['status'] == 'not_used' and 'contains executables' in manifest['sources']['S2']['basis']
    assert manifest['sources']['S3']['status'] == 'none_found'
    assert manifest['counts']['samples'] == 277


def test_sample_check_hashes_bytes_only(tmp_path):
    body = b'\x00invented bytes, not an evtx file\x00'
    folder = tmp_path / 'd' / 'x'
    folder.mkdir(parents=True)
    (folder / '0.evtx').write_bytes(body)
    lock = {'directory': 'd', 'files': [
        {'path': 'x/0.evtx', 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
        {'path': 'x/1.evtx', 'size': 1, 'sha256': '0' * 64}]}
    assert tool.verify_samples(tmp_path, lock) == {'ok': 1, 'missing': 1, 'size_mismatch': 0, 'sha256_mismatch': 0}
    source = (ROOT / 'evaluation/network_expected_detections.py').read_text(encoding='utf-8')
    for forbidden in ('import evtx', 'PyEvtxParser', 'app.engines', 'import detections', 'requests', 'urllib'):
        assert forbidden not in source.split('"""', 2)[2], forbidden
