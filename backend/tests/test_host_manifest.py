"""Per-file technique manifest and frozen selection rule (design host-engine-v1 §3.2, §4, §4.3).

Labels come only from sample file names and folders through a committed keyword table;
no sample is opened. Tests that need the pinned ATT&CK catalogue skip when it is absent.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / 'evaluation/reports/2026-11-host-v1'
spec = importlib.util.spec_from_file_location('host_manifest', ROOT / 'evaluation/host_technique_manifest.py')
manifest_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest_tool)
LOCK = json.loads((ROOT / 'data/evtx-attack-samples-lock.json').read_text(encoding='utf-8'))
CATALOGUE = ROOT / 'data/external/attack/enterprise-attack-20.0.json'
needs_catalogue = pytest.mark.skipif(not CATALOGUE.is_file(), reason='pinned ATT&CK catalogue not installed')


def identity(technique):
    return technique


@pytest.mark.parametrize('path,expected', [
    ('Defense Evasion/DE_1102_security_log_cleared.evtx', {'T1685.005'}),
    ('Defense Evasion/DE_104_system_log_cleared.evtx', {'T1685.005'}),
    ('Credential Access/kerberos_pwd_spray_4771.evtx', {'T1110.003'}),
    ('Persistence/Network_Service_Guest_added_to_admins_4732.evtx', {'T1098.007'}),
    ('Execution/temp_scheduled_task_4698_4699.evtx', {'T1053.005'}),
    ('Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx', {'T1204.002', 'T1218.005', 'T1218.011', 'T1021.003'}),
    ('Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx', {'T1057'}),
    ('Execution/susp_explorer_exec_root_cmdline_@rimpq_@CyberRaiju.evtx', {'T1202'}),
    ('Privilege Escalation/Sysmon_UACME_22.evtx', {'T1548.002'}),
    ('Execution/sysmon_zipexec.evtx', set()),
])
def test_labels_come_from_names_through_the_keyword_table(path, expected):
    techniques, sources = manifest_tool.label(path, identity)
    assert set(techniques) == expected
    assert all(source['keyword'] and source['techniques'] for source in sources)


@needs_catalogue
def test_explicit_ids_in_names_are_resolved_through_revocations():
    from app.engines.host.sigma_harness import load_remap
    resolve = load_remap().resolve
    assert manifest_tool.label('Privilege Escalation/4765_sidhistory_add_t1178.evtx', resolve)[0] == ['T1134.005']
    assert manifest_tool.label('Defense Evasion/Win_4985_T1186_Process_Doppelganging.evtx', resolve)[0] == \
        ['T1055.013']
    assert manifest_tool.label('Credential Access/4794_DSRM_password_change_t1098.evtx', resolve)[0] == ['T1098']


@needs_catalogue
def test_every_keyword_technique_is_active_in_v20():
    from app.engines.host.sigma_harness import load_remap
    remap = load_remap()
    for keyword, techniques in manifest_tool.KEYWORDS:
        for technique in techniques:
            assert remap.resolve(technique) == technique, (keyword, technique)


def test_split_is_by_the_last_hex_digit_of_the_content_hash():
    assert manifest_tool.split_of('0' * 63 + 'a') == 'development'
    assert manifest_tool.split_of('0' * 63 + '8') == 'development'
    assert manifest_tool.split_of('0' * 63 + 'b') == 'report'
    assert manifest_tool.split_of('0' * 63 + '1') == 'report'


def test_committed_manifest_covers_every_pinned_sample_once():
    manifest = json.loads((REPORT / 'technique_manifest.json').read_text(encoding='utf-8'))
    pinned = {f['sha256'] for f in LOCK['files'] if f['path'].endswith('.evtx')}
    samples = manifest['samples']
    assert {s['sha256'] for s in samples} == pinned and len(samples) == len(pinned)
    paths = sorted(p for s in samples for p in s['paths'])
    assert paths == sorted(f['path'] for f in LOCK['files'] if f['path'].endswith('.evtx'))
    for sample in samples:
        assert sample['split'] == manifest_tool.split_of(sample['sha256'])
        assert (sample['status'] == 'labelled') == bool(sample['techniques'])
    counts = manifest['counts']
    assert counts['samples'] == len(samples) and counts['paths'] == len(paths)
    assert counts['labelled'] + counts['excluded_undetermined'] == len(samples)
    assert manifest['commit'] == LOCK['commit'] and manifest['attack_version'] == '20.0'


@needs_catalogue
def test_committed_manifest_is_reproducible_from_the_lock_and_catalogue():
    from app.engines.host.sigma_harness import load_remap
    committed = json.loads((REPORT / 'technique_manifest.json').read_text(encoding='utf-8'))
    assert manifest_tool.build(LOCK, load_remap().resolve) == committed


def test_manifest_builder_never_opens_samples():
    source = (ROOT / 'evaluation/host_technique_manifest.py').read_text(encoding='utf-8')
    for forbidden in ('import evtx', 'from evtx', 'read_bytes', 'open(', 'data/external/evtx'):
        assert forbidden not in source


def test_frozen_files_match_their_recorded_hashes():
    freeze = json.loads((REPORT / 'FREEZE.json').read_text(encoding='utf-8'))
    for name in ('selection_rule.md', 'technique_manifest.json'):
        body = (REPORT / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == freeze['files'][name]['sha256'], name
    rule = (REPORT / 'selection_rule.md').read_text(encoding='utf-8')
    assert rule.startswith('## 4. Frozen evaluation and selection rule')
    assert '### 4.6 Output' in rule and '## 5.' not in rule
    assert freeze['measurements_before_freeze'] == 'none'


def test_frozen_rule_is_the_design_section_at_freeze_time():
    """Until a dated amendment re-freezes it, §4 of the design must equal the frozen copy."""
    design = (ROOT / 'docs/design/host-engine-v1.md').read_text(encoding='utf-8').replace('\r\n', '\n')
    start = design.index('## 4. Frozen evaluation and selection rule')
    section = design[start:design.index('\n## 5. ', start) + 1]
    frozen = (REPORT / 'selection_rule.md').read_text(encoding='utf-8').replace('\r\n', '\n')
    assert section == frozen


def test_amendment_3_cites_the_previous_frozen_rule_hash():
    freeze = json.loads((REPORT / 'FREEZE.json').read_text(encoding='utf-8'))
    previous = 'deece958a570ef97790029bf312164de85636e9d98eedb7951e08af94d0449ab'
    history = freeze['amendments']
    assert [a['amendment'] for a in history] == [3]
    assert history[0]['previous_selection_rule_sha256'] == previous
    assert history[0]['selection_rule_sha256'] == freeze['files']['selection_rule.md']['sha256'] != previous
    assert history[0]['measurements_before_amendment'] == 'none'
    rule = (REPORT / 'selection_rule.md').read_text(encoding='utf-8')
    assert '### 4.8 Per-rule owner review (amendment 3, 24 November 2026)' in rule and previous in rule
