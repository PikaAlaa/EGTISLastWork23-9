"""defang-v1 display rules (design core-v2 §4.2, step 1). All values are invented."""
import json
from pathlib import Path

import pytest

from app.core.defang import RULES_VERSION, defang, refang

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / 'docs/design/defang-cases.json').read_text(encoding='utf-8'))
IDS = [f"{c['type']}:{c['canonical']}" for c in CASES['cases']]
REVERSIBLE = ('url', 'domain', 'ip', 'email')


def test_case_table_is_this_version():
    assert CASES['version'] == RULES_VERSION == 'defang-v1'
    assert {c['type'] for c in CASES['cases']} == {'url', 'domain', 'ip', 'email', 'phone', 'hash'}


@pytest.mark.parametrize('case', CASES['cases'], ids=IDS)
def test_every_case_in_the_table(case):
    assert defang(case['type'], case['canonical']) == case['displayed']


@pytest.mark.parametrize('case', CASES['cases'], ids=IDS)
def test_idempotent(case):
    once = defang(case['type'], case['canonical'])
    assert defang(case['type'], once) == once


@pytest.mark.parametrize('case', [c for c in CASES['cases'] if c['type'] in REVERSIBLE],
                         ids=[i for i, c in zip(IDS, CASES['cases']) if c['type'] in REVERSIBLE])
def test_refang_restores_the_canonical_value(case):
    assert refang(defang(case['type'], case['canonical'])) == case['canonical']


def test_unicode_hosts_are_shown_as_idna_ascii():
    assert defang('domain', 'bücher.example') == 'xn--bcher-kva[.]example'
    assert defang('url', 'https://bücher.example/x') == 'hxxps://xn--bcher-kva[.]example/x'
    assert defang('email', 'info@bücher.example') == 'info[@]xn--bcher-kva[.]example'
    for shown in (defang('domain', 'bücher.example'), defang('url', 'https://bücher.example/x')):
        assert shown.isascii()


def test_path_query_and_fragment_dots_are_unchanged():
    shown = defang('url', 'https://evil.example/dir.v2/file.tar.gz?next=a.b#c.d')
    assert shown == 'hxxps://evil[.]example/dir.v2/file.tar.gz?next=a.b#c.d'


def test_userinfo_at_sign_and_port_colon():
    shown = defang('url', 'https://user@evil.example:8443/')
    assert shown == 'hxxps://user[@]evil[.]example:8443/'
    assert '[:]' not in shown


def test_ipv6_every_colon_and_ipv4_last_dot_only():
    assert defang('ip', '2001:db8:0:1::7') == '2001[:]db8[:]0[:]1[:][:]7'
    assert defang('ip', '198.51.100.20') == '198.51.100[.]20'


def test_no_scheme_or_dot_left_live():
    for case in CASES['cases']:
        if case['type'] in ('url', 'domain', 'email'):
            shown = defang(case['type'], case['canonical'])
            assert '://' not in shown or shown.split('://', 1)[0] in ('hxxp', 'hxxps', 'fxp')
            host_part = shown.split('://', 1)[-1].split('/', 1)[0].split('[@]')[-1]
            assert '.' not in host_part.replace('[.]', '')


def test_refang_handles_the_extract_links_forms_and_more():
    assert refang('hxxps://evil[.]example/x') == 'https://evil.example/x'
    assert refang('HXXP://evil[.]example') == 'http://evil.example'
    assert refang('fxp://files[.]evil[.]example/') == 'ftp://files.evil.example/'
    assert refang('payroll[@]evil[.]example') == 'payroll@evil.example'
    assert refang('2001[:]db8[:][:]1') == '2001:db8::1'
    assert refang('  evil.example ') == 'evil.example'


@pytest.mark.parametrize('kind', ['hash', 'phone', 'sms', 'unknown'])
def test_other_types_are_returned_unchanged(kind):
    assert defang(kind, 'evil.example') == 'evil.example'


@pytest.mark.parametrize('value', [None, 3, b'evil.example'])
def test_non_strings_are_refused(value):
    with pytest.raises(ValueError):
        defang('domain', value)
    with pytest.raises(ValueError):
        refang(value)
