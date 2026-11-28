// defang-v1 console rules (docs/design/core-v2.md §4.2, step 9). Every value is invented and uses
// reserved documentation names and addresses. Run:
//   node --experimental-strip-types --test tests/defang.test.mts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DEFANG_VERSION, defang, guessIndicatorType, refang } from '../src/api/defang.ts';

const cases = JSON.parse(readFileSync(new URL('../../docs/design/defang-cases.json', import.meta.url), 'utf-8'));
const REVERSIBLE = new Set(['url', 'domain', 'ip', 'email']);

test('case table is defang-v1', () => {
  assert.equal(cases.version, DEFANG_VERSION);
  assert.ok(cases.cases.length >= 19);
});

for (const c of cases.cases) {
  test(`table case ${c.type}: ${c.canonical}`, () => {
    assert.equal(defang(c.type, c.canonical), c.displayed);
  });
  test(`idempotent ${c.type}: ${c.canonical}`, () => {
    const once = defang(c.type, c.canonical);
    assert.equal(defang(c.type, once), once);
  });
  if (REVERSIBLE.has(c.type)) {
    test(`refang restores ${c.type}: ${c.canonical}`, () => {
      assert.equal(refang(defang(c.type, c.canonical)), c.canonical);
    });
  }
}

test('unicode hosts are shown as IDNA ASCII', () => {
  assert.equal(defang('domain', 'bücher.example'), 'xn--bcher-kva[.]example');
  assert.equal(defang('url', 'https://bücher.example/x'), 'hxxps://xn--bcher-kva[.]example/x');
  assert.equal(defang('email', 'info@bücher.example'), 'info[@]xn--bcher-kva[.]example');
});

test('path, query and fragment dots unchanged', () => {
  assert.equal(defang('url', 'https://evil.example/dir.v2/file.tar.gz?next=a.b#c.d'),
    'hxxps://evil[.]example/dir.v2/file.tar.gz?next=a.b#c.d');
});

test('refang handles extract_links forms and more', () => {
  assert.equal(refang('hxxps://evil[.]example/x'), 'https://evil.example/x');
  assert.equal(refang('HXXP://evil[.]example'), 'http://evil.example');
  assert.equal(refang('payroll[@]evil[.]example'), 'payroll@evil.example');
  assert.equal(refang('2001[:]db8[:][:]1'), '2001:db8::1');
});

test('other types unchanged', () => {
  for (const type of ['hash', 'phone', 'text', 'sms']) assert.equal(defang(type, 'evil.example'), 'evil.example');
});

test('guessIndicatorType picks the display rule only', () => {
  assert.equal(guessIndicatorType('https://evil.example/a'), 'url');
  assert.equal(guessIndicatorType('hxxps://evil[.]example/a'), 'url');
  assert.equal(guessIndicatorType('evil.example'), 'domain');
  assert.equal(guessIndicatorType('203.0.113.7'), 'ip');
  assert.equal(guessIndicatorType('2001:db8::1'), 'ip');
  assert.equal(guessIndicatorType('payroll@evil.example'), 'email');
  assert.equal(guessIndicatorType('+20 100 000 0000'), 'phone');
  assert.equal(guessIndicatorType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 'hash');
  assert.equal(guessIndicatorType('invented note'), 'text');
});
