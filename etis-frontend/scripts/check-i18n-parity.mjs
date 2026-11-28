// i18n key parity between ar.json and en.json (docs/design/core-v2.md §6 step 10).
//
// Every key must exist in both locales. Plural forms are compared by base key, because Arabic
// uses zero/one/two/few/many/other while English uses one/other. Run:
//   node scripts/check-i18n-parity.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PLURAL = /_(zero|one|two|few|many|other)$/;

export function keySet(tree, prefix = '') {
  const keys = new Set();
  for (const [key, value] of Object.entries(tree)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object') for (const k of keySet(value, path)) keys.add(k);
    else keys.add(path.replace(PLURAL, ''));
  }
  return keys;
}

export function parity(a, b) {
  const left = keySet(a);
  const right = keySet(b);
  return {
    onlyInFirst: [...left].filter((k) => !right.has(k)).sort(),
    onlyInSecond: [...right].filter((k) => !left.has(k)).sort(),
  };
}

export function loadLocales() {
  const read = (lang) => JSON.parse(readFileSync(new URL(`../src/i18n/locales/${lang}.json`, import.meta.url), 'utf-8'));
  return { ar: read('ar'), en: read('en') };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { ar, en } = loadLocales();
  const { onlyInFirst, onlyInSecond } = parity(ar, en);
  for (const k of onlyInFirst) console.error(`only in ar.json: ${k}`);
  for (const k of onlyInSecond) console.error(`only in en.json: ${k}`);
  const problems = onlyInFirst.length + onlyInSecond.length;
  console.log(problems ? `${problems} i18n key(s) missing a translation` : `i18n parity: ok (${keySet(en).size} keys)`);
  process.exit(problems ? 1 : 0);
}
