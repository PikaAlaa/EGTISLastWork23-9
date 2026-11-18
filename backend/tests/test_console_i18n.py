"""SOC console strings exist in both Arabic and English (design core-v1 §9.12)."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LOCALES = ROOT / 'etis-frontend/src/i18n/locales'
PAGES = ROOT / 'etis-frontend/src/pages'
CONSOLE_SECTIONS = ['soc', 'incidents', 'indicators', 'attack']
CONSOLE_PAGES = ['IncidentsPage.tsx', 'IndicatorsPage.tsx', 'AttackPage.tsx']
PLURAL = re.compile(r'_(zero|one|two|few|many|other)$')


def flatten(node, prefix=''):
    keys = set()
    for key, value in node.items():
        path = f'{prefix}{key}'
        keys |= flatten(value, path + '.') if isinstance(value, dict) else {PLURAL.sub('', path)}
    return keys


def locale(name):
    return json.loads((LOCALES / f'{name}.json').read_text(encoding='utf-8'))


EN, AR = locale('en'), locale('ar')


@pytest.mark.parametrize('section', CONSOLE_SECTIONS)
def test_console_sections_have_identical_keys(section):
    if section not in EN and section not in AR:
        pytest.skip(f'{section} strings are added with their page')
    assert flatten(EN[section], section + '.') == flatten(AR[section], section + '.')


def test_navigation_labels_exist_in_both_languages():
    assert set(EN['nav']) == set(AR['nav'])


def emitted_reason_codes():
    """Every code that can reach evidence.reasons: decisive, supporting and unavailable codes."""
    app = ROOT / 'backend/app'
    source = ''.join((app / p).read_text(encoding='utf-8') for p in (
        'engines/risk_scoring.py', 'engines/threat_intel/blacklist_lookup.py', 'core/url_utils.py'))
    codes = set(re.findall(r"(?:decisive|supporting|unavailable|invalid)\.append\('([a-z_]+)'\)", source))
    codes |= set(re.findall(r"'reason':\s*'([a-z_]+)'", source)) | set(re.findall(r"'(blacklist_[a-z_]+)'", source))
    brand = (app / 'engines/rule_based/domain_typosquatting_detector.py').read_text(encoding='utf-8')
    codes |= set(re.findall(r"technique, score, decisive = '([a-z_]+)', 95\.0, True", brand))
    return codes | {'no_warning_signs'}


def test_every_reason_code_is_translated():
    codes = emitted_reason_codes()
    assert {'text_high_corroborated', 'url_model', 'blacklist_exact', 'userinfo_brand'} <= codes  # extraction works
    for name, data in (('en', EN), ('ar', AR)):
        assert not sorted(codes - set(data['reason'])), name


@pytest.mark.parametrize('page', CONSOLE_PAGES + ['../components/InertValue.tsx'])
def test_console_pages_render_indicators_inert(page):
    source = (PAGES / page).read_text(encoding='utf-8')
    for forbidden in ('<a ', 'href', 'component="a"', "component='a'", '<Link', 'window.open', 'target="_blank"'):
        assert forbidden not in source, f'{page} contains {forbidden!r}'


def test_attack_page_shows_the_mitre_copyright_notice():
    source = (PAGES / 'AttackPage.tsx').read_text(encoding='utf-8')
    assert '{coverage.copyright}' in source


@pytest.mark.parametrize('page', CONSOLE_PAGES)
def test_every_literal_key_used_by_a_console_page_exists(page):
    path = PAGES / page
    if not path.exists():
        pytest.skip(f'{page} is added in a later step')
    used = set(re.findall(r"""\bt\(\s*'([a-zA-Z0-9_.-]+)'""", path.read_text(encoding='utf-8')))
    for name, data in (('en', EN), ('ar', AR)):
        missing = sorted(key for key in used if key not in flatten(data))
        assert not missing, f'{name}: {missing}'
