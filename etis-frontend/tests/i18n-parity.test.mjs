// i18n parity (docs/design/core-v2.md §6 step 10): every key in both ar.json and en.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keySet, loadLocales, parity } from '../scripts/check-i18n-parity.mjs';

const { ar, en } = loadLocales();

test('ar.json and en.json have the same keys (plural forms by base key)', () => {
  assert.deepEqual(parity(ar, en), { onlyInFirst: [], onlyInSecond: [] });
});

test('parity detects a key missing in one locale', () => {
  assert.deepEqual(parity({ a: { b: 'x', c: 'y' } }, { a: { b: 'x' } }), { onlyInFirst: ['a.c'], onlyInSecond: [] });
  assert.deepEqual(parity({ d_zero: '', d_few: '', d_other: '' }, { d_one: '', d_other: '' }),
    { onlyInFirst: [], onlyInSecond: [] });
});

test('every literal key used by the new core v2 console code exists in both locales', () => {
  const files = ['src/pages/DevicesPage.tsx', 'src/components/RecommendedActions.tsx', 'src/components/IndicatorValue.tsx'];
  const arKeys = keySet(ar);
  const enKeys = keySet(en);
  const used = new Set();
  for (const file of files) {
    const source = readFileSync(new URL(`../${file}`, import.meta.url), 'utf-8');
    for (const match of source.matchAll(/\bt\('([A-Za-z0-9_.]+)'/g)) used.add(match[1]);
  }
  assert.ok(used.size >= 30, `found ${used.size} keys`);
  for (const key of used) {
    assert.ok(arKeys.has(key), `ar.json is missing ${key}`);
    assert.ok(enKeys.has(key), `en.json is missing ${key}`);
  }
});

test('the toggle labels name the target language in that language', () => {
  for (const locale of [ar, en]) {
    assert.equal(locale.actions.showEnglish, 'Show in English');
    assert.equal(locale.actions.showArabic, 'عرض بالعربية');
  }
});
