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


@pytest.mark.parametrize('page', CONSOLE_PAGES)
def test_every_literal_key_used_by_a_console_page_exists(page):
    path = PAGES / page
    if not path.exists():
        pytest.skip(f'{page} is added in a later step')
    used = set(re.findall(r"""\bt\(\s*'([a-zA-Z0-9_.-]+)'""", path.read_text(encoding='utf-8')))
    for name, data in (('en', EN), ('ar', AR)):
        missing = sorted(key for key in used if key not in flatten(data))
        assert not missing, f'{name}: {missing}'
