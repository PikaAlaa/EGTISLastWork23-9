"""Sigma evaluation harness on in-memory SQLite (design host-engine-v1 §2.2-2.3, §4.2, §5.2, §8.4).

Every rule below is an invented Sigma-format test rule written for these tests; no SigmaHQ
rule text is used. ATT&CK ids come from the committed v20.0 host subset fixture.
"""
import hashlib
import json
import socket
from datetime import timedelta
from pathlib import Path

import pytest

from app.engines.host import sigma_harness as harness
from app.engines.host.detections import NATIVE_RULES
from app.engines.host.pseudonyms import Pseudonymizer
from app.engines.host.sigma_harness import (RuleFile, TARGET_TECHNIQUES, TechniqueRemap, build_candidates,
                                            evaluate, load_remap)
from host_fixtures import T0

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / 'backend/tests/fixtures/attack-20.0-host-subset.json').read_text(encoding='utf-8'))
REMAP = TechniqueRemap.from_objects(FIXTURE['objects'])
PSEUDO = Pseudonymizer(bytes(range(32)))
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
PS = 'Microsoft-Windows-PowerShell/Operational'
MARKER = 'invented-marker-6613'


def rule_yaml(n, *, logsource, detection, status='test', level='high', tags=('attack.t1204.002',),
              author='ETIS tests (invented rule)'):
    lines = [f'title: Invented rule {n}', f'id: 00000000-0000-4000-8000-{n:012d}', f'status: {status}',
             f'level: {level}', f'author: {author}', 'tags:'] + [f'  - {t}' for t in tags] + \
            ['logsource:'] + [f'  {k}: {v}' for k, v in logsource.items()] + ['detection:'] + \
            ['  ' + line for line in detection.strip('\n').splitlines()]
    return '\n'.join(lines) + '\n'


def rule_file(n, path=None, **kwargs):
    text = rule_yaml(n, **kwargs)
    return RuleFile(path=path or f'rules/windows/invented/rule_{n}.yml', text=text,
                    sha256=hashlib.sha256(text.encode('utf-8')).hexdigest())


OFFICE_CHILD = dict(logsource={'product': 'windows', 'category': 'process_creation'}, detection="""
sel:
  ParentImage|endswith: '\\winword.exe'
  Image|endswith: '\\cmd.exe'
condition: sel
""")
FAILED_LOGON = dict(logsource={'product': 'windows', 'service': 'security'}, tags=('attack.t1110.001',),
                    level='medium', status='stable', detection="""
sel:
  EventID: 4625
  LogonType: 3
  Provider_Name: Microsoft-Windows-Security-Auditing
condition: sel
""")
SCRIPT_BLOCK = dict(logsource={'product': 'windows', 'category': 'ps_script'}, tags=('attack.t1059.001',),
                    detection="""
sel:
  ScriptBlockText|contains: 'invented-cradle'
condition: sel
""")
REGEX = dict(logsource={'product': 'windows', 'category': 'process_creation'}, tags=('attack.t1059.003',),
             detection="""
sel:
  CommandLine|re: 'echo [0-9]{3}-invented'
condition: sel
""")


def rec(event_id, channel, n, seconds=0, **fields):
    when = (T0 + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    provider = {'Security': 'Microsoft-Windows-Security-Auditing', SYSMON: 'Microsoft-Windows-Sysmon',
                PS: 'Microsoft-Windows-PowerShell'}.get(channel, 'Invented')
    return {'Channel': channel, 'Provider': provider, 'EventID': event_id, 'TimeCreated': when, 'EventRecordID': n,
            'Computer': 'INVENTED-PC', **fields}


RECORDS = [
    rec(1, SYSMON, 1, Image='C:\\WINDOWS\\System32\\CMD.EXE', ParentImage='C:\\Office\\WINWORD.EXE',
        CommandLine='cmd /c echo 123-invented'),
    rec(4688, 'Security', 2, NewProcessName='C:\\Windows\\System32\\cmd.exe',
        ParentProcessName='C:\\Office\\winword.exe', CommandLine='cmd'),
    rec(4688, 'Security', 3, NewProcessName='C:\\Windows\\System32\\cmd.exe',
        ParentProcessName='C:\\Windows\\explorer.exe', CommandLine='cmd'),
    rec(4625, 'Security', 4, LogonType='3', TargetUserName='invented-user'),
    rec(4625, 'Security', 5, LogonType='2', TargetUserName='invented-user'),
    rec(4625, 'System', 6, LogonType='3'),  # same id and fields in another channel
    rec(4104, PS, 7, ScriptBlockText='iex (invented-cradle)'),
    rec(4104, 'Security', 8, ScriptBlockText='iex (invented-cradle)'),  # wrong channel
    rec(1, 'Security', 9, Image='C:\\x\\cmd.exe', ParentImage='C:\\x\\winword.exe'),  # Sysmon id outside Sysmon
]


def matches(alerts):
    return sorted((a.facts['sigma']['id'][-2:], a.record_ids[0]) for a in alerts)


def select(*files, **kwargs):
    return build_candidates(list(files), REMAP, release_tag='r-invented', **kwargs)


def test_candidates_convert_and_match_only_their_own_channel_and_event_ids():
    selection = select(rule_file(1, **OFFICE_CHILD), rule_file(2, **FAILED_LOGON), rule_file(3, **SCRIPT_BLOCK),
                       rule_file(4, **REGEX))
    assert [c.rule_id[-1] for c in selection.candidates] == ['1', '2', '3', '4'] and not selection.excluded
    alerts = evaluate(selection.candidates, RECORDS, PSEUDO)
    # Rule 1 matches Sysmon 1 (record 1) and 4688 (record 2) case-insensitively; rule 2 only the
    # Security 4625 with LogonType 3; rule 3 only the PowerShell channel; rule 4 needs REGEXP.
    assert matches(alerts) == [('01', 1), ('01', 2), ('02', 4), ('03', 7), ('04', 1)]


def test_process_creation_rules_get_a_sysmon_and_a_security_4688_query():
    candidate = select(rule_file(1, **OFFICE_CHILD)).candidates[0]
    assert len(candidate.queries) == 2
    assert any("Channel='Microsoft-Windows-Sysmon/Operational'" in q and 'EventID=1' in q for q in candidate.queries)
    assert any("Channel='Security'" in q and 'EventID=4688' in q and 'NewProcessName' in q for q in candidate.queries)


def test_every_sigma_alert_carries_the_attribution_block():
    selection = select(rule_file(1, **OFFICE_CHILD), rule_file(2, **FAILED_LOGON))
    alerts = evaluate(selection.candidates, RECORDS, PSEUDO)
    assert alerts
    for alert in alerts:
        sigma = alert.facts['sigma']
        assert set(sigma) == {'id', 'title', 'author', 'level', 'status', 'release', 'path', 'sha256', 'license',
                              'source'}
        assert sigma['author'] == 'ETIS tests (invented rule)' and sigma['license'] == 'DRL-1.1'
        assert sigma['release'] == 'r-invented' and sigma['path'].startswith('rules/windows/invented/')
        assert sigma['source'] == f"https://github.com/SigmaHQ/sigma/blob/r-invented/{sigma['path']}"
        assert alert.detection == 'sigma:' + sigma['id'] and alert.level == sigma['level']
        assert alert.host_ref == PSEUDO.host_ref('INVENTED-PC')


@pytest.mark.parametrize('kwargs,reason', [
    (dict(OFFICE_CHILD, status='experimental'), 'status'),
    (dict(OFFICE_CHILD, status='deprecated'), 'status'),
    (dict(OFFICE_CHILD, level='low'), 'level'),
    (dict(OFFICE_CHILD, level='informational'), 'level'),
    (dict(OFFICE_CHILD, tags=('attack.execution',)), 'technique'),
    (dict(OFFICE_CHILD, tags=('attack.t1003.001',)), 'technique'),  # not in the target set
    (dict(OFFICE_CHILD, tags=('attack.t9999',)), 'technique'),  # unknown id
    (dict(OFFICE_CHILD, tags=('attack.t1153',)), 'technique'),  # deprecated id
    (dict(OFFICE_CHILD, logsource={'product': 'linux', 'category': 'process_creation'}), 'logsource'),
    (dict(OFFICE_CHILD, logsource={'product': 'windows', 'service': 'application'}), 'logsource'),
    (dict(OFFICE_CHILD, logsource={'product': 'windows', 'category': 'antivirus'}), 'logsource'),
    (dict(OFFICE_CHILD, logsource={'product': 'windows', 'service': 'security'},
          detection="keywords:\n  - invented\ncondition: keywords\n"), 'conversion_failed'),
    (dict(OFFICE_CHILD, detection="sel:\n  Image|nosuchmodifier: x\ncondition: sel\n"), 'conversion_failed'),
    (dict(OFFICE_CHILD, detection="sel:\n  Data.Name: x\ncondition: sel\n"), 'unsupported_field_name'),
])
def test_exclusions_are_whole_rule_and_counted(kwargs, reason):
    selection = select(rule_file(1, **OFFICE_CHILD), rule_file(2, **kwargs))
    assert [c.rule_id[-1] for c in selection.candidates] == ['1']
    assert selection.excluded == {reason: 1}
    assert selection.excluded_rules == [('rules/windows/invented/rule_2.yml', reason)]


def test_unparseable_yaml_and_correlation_rules_are_excluded():
    broken = RuleFile(path='rules/broken.yml', text='title: [unclosed', sha256='0' * 64)
    correlation = RuleFile(path='rules/corr.yml', sha256='1' * 64, text='\n'.join([
        'title: Invented correlation', 'id: 00000000-0000-4000-8000-0000000000c1', 'status: test', 'level: high',
        'correlation:', '  type: event_count', '  rules: [00000000-0000-4000-8000-000000000001]',
        '  group-by: [TargetUserName]', '  timespan: 10m', '  condition: {gte: 20}', '']))
    selection = select(rule_file(1, **OFFICE_CHILD), broken, correlation)
    assert selection.excluded == {'conversion_failed': 1, 'correlation': 1}


def test_revocation_remap_comes_from_the_catalogue():
    assert REMAP.resolve('T1562.001') == 'T1685' and REMAP.resolve('T1562') == 'T1685'
    assert REMAP.resolve('T1562.006') == 'T1685' and REMAP.resolve('T1070.001') == 'T1685.005'
    assert REMAP.resolve('T1562.002') == 'T1685.001' and REMAP.resolve('T1059.001') == 'T1059.001'
    assert REMAP.resolve('T1153') is None and REMAP.resolve('T9999') is None
    selection = select(rule_file(1, **dict(OFFICE_CHILD, tags=('attack.defense-evasion', 'attack.t1562.001',
                                                             'attack.t1070.001', 'attack.t1003.001'))))
    assert selection.candidates[0].techniques == ('T1685', 'T1685.005')


def test_remap_loader_verifies_the_pinned_catalogue(tmp_path):
    body = json.dumps({'type': 'bundle', 'objects': FIXTURE['objects']}).encode('utf-8')
    (tmp_path / 'attack').mkdir()
    (tmp_path / 'attack' / 'enterprise-attack-20.0.json').write_bytes(body)
    lock = {'version': '20.0', 'destination': 'attack', 'files': [
        {'collection': 'enterprise', 'file': 'enterprise-attack-20.0.json', 'size': len(body),
         'sha256': hashlib.sha256(body).hexdigest()}]}
    lock_path = tmp_path / 'lock.json'
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    assert load_remap(lock_path, tmp_path).resolve('T1562.001') == 'T1685'
    lock['files'][0]['sha256'] = '0' * 64
    lock_path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError) as exc:
        load_remap(lock_path, tmp_path)
    assert str(exc.value) == 'attack_catalogue_hash_mismatch'


def test_target_set_matches_the_design_and_covers_native_rules():
    assert TARGET_TECHNIQUES == frozenset({
        'T1110.001', 'T1110.003', 'T1136.001', 'T1098.007', 'T1059.001', 'T1027.010', 'T1105', 'T1543.003',
        'T1053.005', 'T1685.005', 'T1685.001', 'T1133', 'T1021.001', 'T1685', 'T1078.003', 'T1204.002',
        'T1059.003', 'T1059.005', 'T1218.005', 'T1490', 'T1134.002', 'T1078'})
    assert {t for rule in NATIVE_RULES for t in rule.techniques} <= TARGET_TECHNIQUES
    assert all(REMAP.resolve(t) == t for t in TARGET_TECHNIQUES)  # every target id is active in v20.0


def test_missing_fields_never_error_and_never_match():
    absent = dict(OFFICE_CHILD, detection="sel:\n  OriginalFileName: 'Cmd.Exe'\ncondition: sel\n")
    not_absent = dict(OFFICE_CHILD, detection="sel:\n  Image|endswith: '\\cmd.exe'\nfilter:\n"
                      "  OriginalFileName: 'Cmd.Exe'\ncondition: sel and not filter\n")
    selection = select(rule_file(1, **absent), rule_file(2, **not_absent))
    assert len(selection.candidates) == 2
    assert matches(evaluate(selection.candidates, RECORDS, PSEUDO)) == [('02', 1), ('02', 2), ('02', 3)]


def test_rule_files_are_never_modified():
    original = rule_file(1, **OFFICE_CHILD)
    selection = select(original)
    assert selection.candidates[0].sha256 == hashlib.sha256(original.text.encode('utf-8')).hexdigest()


def test_alerts_carry_no_event_values():
    records = [rec(1, SYSMON, 1, Image=f'C:\\{MARKER}\\cmd.exe', ParentImage=f'C:\\{MARKER}\\winword.exe',
                   CommandLine=f'cmd /c {MARKER}', User=MARKER)]
    records[0]['Computer'] = MARKER
    alerts = evaluate(select(rule_file(1, **OFFICE_CHILD)).candidates, records, PSEUDO)
    assert len(alerts) == 1 and MARKER not in json.dumps(alerts[0].as_dict())


def test_regexp_is_safe_on_nulls_and_bad_patterns():
    assert harness.regexp('inv[a-z]+', 'xx invented') is True
    assert harness.regexp('inv', None) is False
    assert harness.regexp('(', 'anything') is False


def test_conversion_and_evaluation_need_no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('network access attempted')
    monkeypatch.setattr(socket, 'socket', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    selection = select(rule_file(1, **OFFICE_CHILD), rule_file(3, **SCRIPT_BLOCK))
    assert len(evaluate(selection.candidates, RECORDS, PSEUDO)) == 3


def test_requirements_pin_the_sigma_stack():
    lines = (ROOT / 'requirements-runtime.txt').read_text(encoding='utf-8').splitlines()
    for pin in ('pysigma==2.1.0', 'pysigma-backend-sqlite==2.1.1', 'pysigma-pipeline-windows==3.0.0',
                'pysigma-pipeline-sysmon==3.0.0'):
        assert pin in lines
