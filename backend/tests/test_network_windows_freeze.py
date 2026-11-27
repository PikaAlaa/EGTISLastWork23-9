"""network.windows v1 freeze (design network-windows-v1 §4 incl. §4.11, §9 step 7): FREEZE.json hashes, the
frozen rule equals §4 of the design, and the frozen facts (lists, gate techniques, no expected sample) agree."""
import hashlib
import json
from pathlib import Path

import pytest

from app.engines.network_windows import blocklists, detections
from app.engines.network_windows import engine as nw

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / 'evaluation' / 'reports' / '2026-11-network-windows-v1'
FREEZE = json.loads((REPORT / 'FREEZE.json').read_text(encoding='utf-8'))
LOCK_SHA = '692d3197a7aadbeae5a7803dbc7578395d1d041244ee1b77fb6765a535260b6c'


def _lf(path):
    return path.read_text(encoding='utf-8').replace('\r\n', '\n')


@pytest.mark.parametrize('name', ['selection_rule.md', 'expected_detections.json'])
def test_frozen_files_match_their_recorded_hashes(name):
    assert hashlib.sha256((REPORT / name).read_bytes()).hexdigest() == FREEZE['files'][name]['sha256']


def test_frozen_inputs_match_their_recorded_hashes():
    expected = {'data/network-blocklists-lock.json', 'data/evtx-attack-samples-lock.json',
                'evaluation/reports/2026-11-host-v1/technique_manifest.json',
                'evaluation/network_expected_detections.py', 'requirements-runtime.txt',
                'requirements-windows.lock.txt'} | {
        f'backend/app/engines/network_windows/{m}.py' for m in ('readers', 'detections', 'blocklists', 'engine')}
    assert expected <= set(FREEZE['inputs'])
    for name, entry in FREEZE['inputs'].items():
        assert hashlib.sha256(_lf(ROOT / name).encode('utf-8')).hexdigest() == entry['sha256_lf'], name


def test_the_blocklist_lock_is_pinned_by_its_raw_bytes_as_the_engine_reads_it():
    raw = (ROOT / 'data' / 'network-blocklists-lock.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FREEZE['blocklist_lock']['sha256'] == LOCK_SHA
    specs, lock_sha = blocklists.read_lock()
    assert lock_sha == LOCK_SHA and [s.name for s in specs] == FREEZE['blocklist_lock']['lists'] == ['feodo_tracker']
    assert set(blocklists.ALLOWED) == {'feodo_tracker'}


def test_frozen_rule_is_the_design_section_at_freeze_time():
    """Until a dated amendment re-freezes it, §4 of the design must equal the frozen copy."""
    design = _lf(ROOT / 'docs/design/network-windows-v1.md')
    start = design.index('## 4. Frozen evaluation and selection rule')
    section = design[start:design.index('\n## 5. ', start) + 1]
    assert section == _lf(REPORT / 'selection_rule.md')
    assert '\n## 5.' not in section and '### 4.11 Pre-measurement clarifications (27 November 2026)' in section
    assert FREEZE['measurements_before_freeze'] == 'none' and FREEZE['amendments'] == []


def test_the_rule_names_gate_techniques_lists_and_the_unvalidated_consequence():
    rule = ' '.join(_lf(REPORT / 'selection_rule.md').split())
    assert '**N5 `T1568.002`, N7 `T1571`, N8 `T1071.004`**' in rule and '**exactly**' in rule
    assert LOCK_SHA in rule and 'deprecated on 2025-01-03' in rule
    assert '**No rule has an expected sample** in either half' in rule
    assert '**`unvalidated_on_samples`, with confidence capped at `single_signal`**' in rule
    assert FREEZE['popular_list']['sha256'] in rule
    assert FREEZE['gate_techniques'] == {'N5': ['T1568.002'], 'N7': ['T1571'], 'N8': ['T1071.004'],
                                         'match': 'exact; a parent never matches a sub-technique or the reverse',
                                         'others': 'N1, N2, N3, N4, N6, N9: none'}


def test_expected_detections_agree_with_the_freeze():
    manifest = json.loads((REPORT / 'expected_detections.json').read_text(encoding='utf-8'))
    assert {r: tuple(v['gate_techniques']) for r, v in manifest['rules'].items() if v['gate_techniques']} == \
        {r: tuple(t) for r, t in FREEZE['gate_techniques'].items() if r.startswith('N')}
    assert all(not v['expected_development'] and not v['expected_report'] for v in manifest['rules'].values())
    assert FREEZE['expected_samples']['development'] == FREEZE['expected_samples']['report'] == 0
    assert set(manifest['rules']) == set(detections.DETECTIONS)


def test_frozen_url_model_is_the_engine_pin():
    assert (detections.N4_URL_CANDIDATE, detections.N4_THRESHOLD) == (
        FREEZE['url_model']['candidate'], FREEZE['url_model']['threshold'])
    assert nw.OBSERVATION_KIND == 'windows_network_batch'
